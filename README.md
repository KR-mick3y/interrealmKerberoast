## Inter-realm Kerberoast
교차 도메인 신뢰 관계에서는 krbtgt의 패스워드 해시가 다르기 때문에 레퍼럴 티켓 교환 과정 2단계가 추가되어 커버로스 8단계 인증을 거칩니다.

<img width="518" height="585" alt="image" src="https://github.com/user-attachments/assets/e79e1ab4-25c4-4491-9049-cfa55061cf34" />

레퍼럴 티켓은 상호 규약된 신뢰 키를 통해 암호화 되는데, 이 과정에서 동일 포레스트 내부끼리의 신뢰 키는 자동으로 생성되지만 외부 포레스트의 경우 A 도메인에서 B 도메인의 관리자 계정정보를 통해 원격 작업을 하지 않는 이상 서로가 약속한 신뢰 패스워드를 동일하게 입력하여 신뢰 관계를 구축해야 합니다.

<img width="471" height="187" alt="image" src="https://github.com/user-attachments/assets/844f71ad-45cb-4272-9cac-b4a3e1f970b4" />

이때 평문으로 입력한 신뢰 패스워드는 30일간 유효하며 이후부터는 도메인 컨트롤러에 의해 자동으로 난수로 변경됩니다. 즉, 교차 포레스트에서 신뢰 관계가 구축되었을 때 30일 미만의 경우 레퍼럴 티켓을 발급받은 이후 신뢰 패스워드를 오프라인 해시 크랙할 수 있게 됩니다. 
interrealmKerberoast는 도메인에서 외부 도메인에 대한 서비스 티켓을 요청하여 획득한 암호화된 레퍼럴 티켓으로부터 크랙 가능한 해시캣 포맷의 값을 가져오는 도구입니다.
도구를 사용하기 위해서는 레퍼럴 티켓을 정상적으로 요청할 수 있어야 하기 때문에 최소 1개의 유효한 도메인 계정이 요구됩니다.

## 사용법
이 도구는 다음과 같은 인증 방식을 지원합니다.
- 평문 패스워드
- ntlm hash
- 환경변수에 저장된 커버로스 티켓

```
usage: TrustRoasting.py [-h] -target TARGET_DOMAIN [-dc-ip DC_IP] [-hashes HASHES] [-k] [-ccache CCACHE] [-o OUTPUT] identity

positional arguments:
  identity              domain/user:password or domain/user

options:
  -h, --help            show this help message and exit
  -target TARGET_DOMAIN
  -dc-ip DC_IP
  -hashes HASHES        LMHASH:NTHASH
  -k                    Use Kerberos ccache (KRB5CCNAME)
  -ccache CCACHE        Path to ccache file
  -o, --output OUTPUT
```

해당 도구는 다음과 같은 상황의 경우 예외 처리로 분기됩니다.
- 트러스트 관계 없음
- 동일 포레스트에서의 신뢰 도메인
- 교차 포레스트에서의 신뢰 도메인이며, 30일이 경과된 도메인
