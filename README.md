# Taint_plugin

오염분석 개념을 접목한 gdb플러그인 제작



## 🖥️ 프로그램 소개

오염분석 기능을 모방하여 만든 gdb 플러그인 입니다.

- 개발 의도
  : 오염분석을 바이너리 분석 과정에 사용하면
    입력값이 영향주는 코드를 사전에 파악하면 분석 효율이 높아질까하여 자체 개발 진행해봤습니다.

  



## 🕰️ 개발 기간

- 2023.01.01 ~ 진행중



### ⚙️ 개발 환경

- OS : Ubuntu 22.04.2 LTS
- Python 3.10.6
- gdb 12.1
<br>


## 📌 주요 기능

구조 : TaintReg 주소 {location} [--set] [--monitor] [--clear]

원리 : 외부에 "taint_progress"란 로그 파일를 생성하고 내부에 오염시작주소, 오염레지스터, 오염기록을 통해서 monitoring시 참고하여 판단합니다.



### option

(1) --set

: 현재 명령어 내에 오염이 시작될 레지스터를 지정

<단, 이미 지정되어있었을 경우 taint_progress를 재생성이 필요한데 백업여부를 확인하게 된다.>

<p align="center">
  <img src="https://github.com/Greedun/Taint_plugin/assets/78598657/677e91aa-7965-499b-bf9a-634291a71945" width="500" height="300">
</p>
<br><br>

(2) --monitor

: monitor기능을 on/off

=> 해당 기능이 on이 되었을 경우 gdb가 stop 될 때마다 "hook_stop"함수가 실행

<p align="center">
  <img src="https://github.com/Greedun/Taint_plugin/assets/78598657/6dcf575b-591c-4e39-8216-25b77decb478" width="500" height="250">
</p>
<br><br>

(3) --clear

: "taint_progress"파일을 삭제하여 내부 값을 초기화

<단, 이 옵션은 백업 확인이 없기 때문에 내부 값이 날라갈 수 있습니다.>
<br><br>


### hook_stop

: 지정한 오염원이 진행 중 명령어를 오염시켰다면  
  오염된 명령어를 "taint_progress"에 기록해두고 화면에 오염된 명령어들을 출력

(동작 원리)

1. 명령어 주소가 코드 범위내에 있는지 확인
2. 명령어의 opcode, semantic, 어셈 명령어(inst), 주석등을 추출
3. 만약 명령어가 오염 확인 명령어에 등록되어 있다면
   로드했던 "taint_progress"기반으로 오염될 수 있는지 확인
4. 3번의 경우가 충족된다면 "taint_progress"에 오염 명령어를 추가후 업데이트 
5. 이후에는 상태가 off될 때까지 위 과정 반복

<p align="center">
  <img src="https://github.com/Greedun/Taint_plugin/assets/78598657/e5dc54a3-ebcc-408a-9047-949e31b427a0" width="500" height="250">
</p>
<br><br>

## 오염 확인 명령어

1. 데이터 로드 및 저장 명령어 : MOV, LEA
2. 연산 명령어 : ADD, SUB, MUL, DIV / AND, OR, XOR
3. 분기 및 점프 명령어 : CMP / JMP, JE, JNE, JZ, JNZ
4. 명령어 접근 명령어 : PUSH, POP

=> 메모리 접근과 관련된 LEA, 점프 명령어, 명령어 접근의 경우 개발 예정

