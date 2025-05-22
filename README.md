# How to use?
차단할 도메인들이 담긴 csv파일을 읽어 http(80포트) 통신을 차단하는 프로그램입니다. 

csv파일의 구조는 
`번호,도메인`입니다.
ex)
1,google.com
2,naver.com
3,daum.net

**dependency**

```
sudo apt install libmnl-dev
sudo apt install libnfnetlink-dev
sudo apt install libnetfilter-queue-dev
```
**iptables 설정**
```
iptables -A OUTPUT -j NFQUEUE --queue-num 0
iptables -A INPUT -j NFQUEUE --queue-num 0
```
위 설정이 되어있는지 먼저 확인 해야합니다. (netfilter 큐로 jump시킴)


```.
/실행파일 <차단할 도메인>
ex) ./nft
file : <파일명>
```

# 주의사항
QT creator 환경에서 디버깅했을 때, IDE내에서는 절대 경로를 사용해야 파일을 제대로 가져옵니다. 
다른 IDE는 확인하지 않았으나 segmentation fault가 발생한다면 절대 경로를 입력해보세요
