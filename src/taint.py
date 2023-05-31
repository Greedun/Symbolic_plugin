import importlib
import os
import sys
import json
from datetime import datetime
import shutil
import gdb
import inspect

# 구조 : {'create_date': '', 'start_addr': '', 'set_REG': '', 'total_taint': []}
global_taint_progress = {} # taint_progress에서 load

# taint_progress의 값을 초기화(전역변수))
def init_taint_progress():
    global global_taint_progress
    
    global_taint_progress['create_date'] = ""
    global_taint_progress['start_addr'] = ""
    global_taint_progress['set_REG'] = ""
    global_taint_progress['total_taint'] = []

# 모듈이 없을 경우 자동으로 설치후 import
def import_or_install(package):
    try:
        importlib.import_module(package)
    except ImportError:
        import subprocess
        subprocess.check_call(["pip3", "install", package])
    finally:
        globals()[package] = importlib.import_module(package)
    
    import capstone

# 아키텍처에 따른 모드 값 반환
def gef_to_cs_arch() -> Tuple[str, str, str]:
    if gef.arch.arch == "ARM":
        if isinstance(gef.arch, ARM):
            if gef.arch.is_thumb():
                return "CS_ARCH_ARM", "CS_MODE_THUMB", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
            return "CS_ARCH_ARM", "CS_MODE_ARM", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "ARM64":
        return "CS_ARCH_ARM64", "0", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "X86":
        if gef.arch.mode == "32":
            return "CS_ARCH_X86", "CS_MODE_32", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
        if gef.arch.mode == "64":
            return "CS_ARCH_X86", "CS_MODE_64", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "PPC":
        if gef.arch.mode == "PPC32":
            return "CS_ARCH_PPC", "CS_MODE_PPC32", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
        if gef.arch.mode == "PPC64":
            return "CS_ARCH_PPC", "CS_MODE_PPC64", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "MIPS":
        if gef.arch.mode == "MIPS32":
            return "CS_ARCH_MIPS", "CS_MODE_MIPS32", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
        if gef.arch.mode == "MIPS64":
            return "CS_ARCH_MIPS32", "CS_MODE_MIPS64", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    raise ValueError

def cs_disassemble(location: int, nb_insn: int, **kwargs: Any) -> Generator[Instruction, None, None]:

    # capstone을 gef의 Instruction으로 변환
    def cs_insn_to_gef_insn(cs_insn: capstone.CsInsn) -> Instruction:
        sym_info = gdb_get_location_from_symbol(cs_insn.address)
        loc = "<{}+{}>".format(*sym_info) if sym_info else ""
        ops = [] + cs_insn.op_str.split(", ")
        return Instruction(cs_insn.address, loc, cs_insn.mnemonic, ops, cs_insn.bytes)

    arch_s, mode_s, endian_s = gef_to_cs_arch()
    cs_arch: int = getattr(capstone, arch_s)
    cs_mode: int = getattr(capstone, mode_s)
    cs_endian: int = getattr(capstone, endian_s)

    # location : 현재위치, page_start : page시작점, offset : location은 시작점에서 얼마나 떨어졌는가
    cs = capstone.Cs(cs_arch, cs_mode | cs_endian) # 클래스 반환?
    cs.detail = True
    page_start = align_address_to_page(location)
    offset = location - page_start

    skip = int(kwargs.get("skip", 0)) # skip값 얻기
    nb_prev = int(kwargs.get("nb_prev", 0)) # nb_prev값 얻기
    pc = gef.arch.pc # $pc값 얻기

    if nb_prev > 0:
        location = gdb_get_nth_previous_instruction_address(pc, nb_prev) or -1
        if location < 0:
            err(f"failed to read previous instruction")
            return
        nb_insn += nb_prev
    # code : location부터 바이너리 읽어오는 값 저장
    code = kwargs.get("code", gef.memory.read(
        location, gef.session.pagesize - offset - 1))

    for insn in cs.disasm(code, location):
        if skip:
            skip -= 1
            continue
        nb_insn -= 1
        yield cs_insn_to_gef_insn(insn)
        if nb_insn == 0:
            break
    return

# 코드영역 주소 추출하는 코드(임시)
def export_location_opcode_value():
    code_section = []
    vmmap = gef.memory.maps
    if not vmmap:
        err("No address mapping information found")
        return

    # code영역 주소 추출
    for entry in vmmap:
        if "/usr/lib/x86_64-linux-gnu/libc.so.6" in entry.path:
            break
        l = [hex(entry.page_start),hex(entry.page_end),hex(entry.offset),str(entry.permission),str(entry.path)]
        code_section.append(l)
        del l
        #print(f"{hex(entry.page_start)}\t{hex(entry.page_end)}\t{hex(entry.offset)}\t\t{entry.permission}\t\t{entry.path}")
    start_codeaddr = code_section[0][0] # 시작
    end_codeaddr = code_section[len(code_section)-1][1] #마지막
    return [start_codeaddr,end_codeaddr]

# insn내부 값 확인 용도
def confirm_inst(insn):
    print(f"Address : {hex(insn.address)}")
    print(f"is_valid : {insn.is_valid}") # ?
    print(f"Location : {insn.location}")
    print(f"mnemonic : {insn.mnemonic}")
    print(f"opcode : {insn.opcodes}")
    print(f"operand : {insn.operands}")
    print(f"size : {insn.size}")
    print()

def check_location(location):
    code_section = export_location_opcode_value() # 코드 영역 경계(리스트)
    code_start = int(code_section[0],16)
    code_end = int(code_section[1],16)
    
    if location < code_start and location > code_end:
        return False
    
    return True

def check_flag(list_flag):
    # [monitor_flag, set_flag, clear_flag] - 4, 2, 1
    # 순위 : clear -> set -> monitor
    # clear => TaintReg --clear
    # set => TaintReg location($pc) --set Reg
    # monitor => TaintReg --monitor
    status = ""
    if list_flag[0] == True: # monitor
        status += "1"
    else:
        status += "0"
    
    if list_flag[1] != "": # set
        status += "1"
    else:
        status += "0"
    
    if list_flag[2] == True: # clear
        status += "1"
    else:
        status += "0"

    return status

def createDirectory(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print("Error: Failed to create the directory.")

# --------------------
    
class Taint_function:
    # 코드 마무리시 여태까지 기록을 업데이트하는 기능
    def finish_taint_progress(self):
        global global_taint_progress
        
        with open("taint_progress", 'w') as f:
            #print(global_taint_progress)
            json.dump(global_taint_progress, f, indent=4)
        return 
    
    # taint_progress파일 관련
    def load_taint_progress(self):
        global global_taint_progress
        # (check) taint_progress파일이 있는지 확인 없다면 생성
        if not os.path.exists("taint_progress"):
            self.make_taint_progress()
            
        else:
            # load
            while True:
                print("[*] taint_progress파일이 존재하여 다음 선택지 중 골라주세요.")
                print("1. 기존 taint_progress를 load")
                print("2. taint_progress파일 삭제후 새로 생성")
                print("3. taint_progress파일 백업후 새로 생성")
                confirm = int(input(">> "))
                
                if confirm != 1 or confirm != 2 or confirm != 3:
                    break
                else:
                    print("[!] 잘못된 입력값 입니다.\n")

            if confirm == 1:
                # 기존 load
                with open("./taint_progress") as f:
                    global_taint_progress = json.load(f) # type : dict
                
            elif confirm == 2:
                # 삭제후 생성
                if os.path.isfile("taint_progress"):
                    os.remove("taint_progress")
                    self.make_taint_progress()
                    
                else:
                    print("[!] taint_progress파일이 존재하지 않습니다.")

            elif confirm == 3:
                cur_path = os.getcwd() # 현재 경로
                date = datetime.today().strftime("%Y.%m.%d-%H:%M:%S")
                change_name = date + "_taint_progress"
                
                createDirectory("log") # 백업폴더(log)생성
                
                # Log폴더에 따로 기록
                shutil.copyfile("./taint_progress","./log/"+change_name)
                
                # 기존 파일 삭제
                os.remove("taint_progress")
                
                # progress파일 새로 생성
                self.make_taint_progress()
                
                gef_print(f"{change_name} 파일로 백업되었습니다.")
                
            else:
                # 잘못된 입력값
                gef_print("[!] 잘못된 선택지 입니다.")
            print()
            
    def make_taint_progress(self):
        # Frame을 해당 파일에 적기(json형태)
        create_date = datetime.today().strftime("%Y.%m.%d-%H:%M:%S")

        frame_taint_progress = {
            "create_date" : create_date,
            "start_addr" : "", # 오염 시작 지점(어셈블리어)
            "set_REG" : "", # 오염 내부 REG
            "total_taint" : [], #오염된 주소 수집 -> 내부형태 [주소, 어셈블리어, 오염부분]
        }
        
        with open("taint_progress", 'w') as f:
            json.dump(frame_taint_progress, f, indent=4)
        
        gef_print("[+] Create 'taint_progress' file")

    # 기능별 함수 구분
    def function_set(self, location, list_result_ds, set_flag):
        global global_taint_progress
        
        insns = [] # INSTRUCTION 클래스가 들어감
        opcodes_len = 0
        length = 1
        for insn in list_result_ds: # DISASSEMBLY 핵심
            insns.append(insn)
            opcodes_len = max(opcodes_len, len(insn.opcodes)) # ?
        
        show_opcodes = True
        insn = insns[0]
        dict_insn = {}
        dict_key = ['addr','opcode','location','inst','semantic']
        dict_insn['semantic'] = []
        
        insn_fmt = f"{{:{opcodes_len}o}}" if show_opcodes else "{}"
        text_insn = insn_fmt.format(insn)
        list_insn = list(filter(lambda x: x!='',text_insn.split(" "))) # ''는 리스트에서 필터링처리
        for i in range(len(list_insn)):
            if i < 4:
                dict_insn[dict_key[i]]=list_insn[i]
            else:
                list_insn[i] = list_insn[i].replace(',','')
                dict_insn['semantic'].append(list_insn[i])
        # print(dict_insn) # 주요 정보 모음
        # ----------
        
        exist_REG = 0 # 해당 주소에 REG확인하는 변수
        # set할 레지스터에 있는지 확인
        for semantic in dict_insn['semantic']:
            if semantic == set_flag.lower():
                exist_REG += 1

        if exist_REG == 0:
            gef_print("[!] 오염시킬 주소에 해당 레지스터는 존재하지 않습니다.")
            return
        
        if global_taint_progress['set_REG'] != "":
            # 이미 설정된 값이 있다면 
            # 1) 백업 여부 확인
            print("[*] 기록된 taint_progress를 백업하실려면 Y를 입력해주세요")
            sel = input(">> ")
            if sel == "Y":
                cur_path = os.getcwd() # 현재 경로
                date = datetime.today().strftime("%Y.%m.%d-%H:%M:%S")
                change_name = date + "_taint_progress"
                
                createDirectory("log") # 백업폴더(log)생성
                
                # Log폴더에 따로 기록
                shutil.copyfile("./taint_progress","./log/"+change_name)
                
                # 기존 파일 삭제
                os.remove("taint_progress")
                
                # progress파일 새로 생성
                self.make_taint_progress()
                
                gef_print(f"{change_name} 파일로 백업되었습니다.")
            else:
                print("[*] 값을 초기화 후 진행합니다.")
                # 백업없이 값 초기화
                init_taint_progress()
            
        # 설정된 값이 없는 경우
        global_taint_progress['set_REG'] = set_flag
        global_taint_progress['start_addr'] = dict_insn['addr']
        global_taint_progress['total_taint'].append(dict_insn)
        
        self.finish_taint_progress() # Last

    def function_clear(self):
        global global_taint_progress
        
        # "taint_progress"파일을 삭제후 다시 생성
        if os.path.isfile("taint_progress"):
            os.remove("taint_progress")
            self.make_taint_progress()
        else:
            print("[!] taint_progress파일이 존재하지 않습니다.")
        
        self.finish_taint_progress() # Last

    def confirm_register_function(self):
        status = ''

        try:
            gdb.events.stop.disconnect(hook_stop)
            
            # 내부에 등록된 함수가 있다는 뜻
            gdb.events.stop.connect(hook_stop)
            status = "on"
            
        except Exception as ex:
            # 내부에 등록된 함수가 하나도 없다는 의미
            status = "off"
        
        return status

class Taint_Reg(GenericCommand):
    
    """Dummy new command."""
    _cmdline_ = "TaintReg"
    _syntax_  = f"{_cmdline_} [location] [--set] [--monitor] [--clear]"
    
    @only_if_gdb_running
    @parse_arguments({("location"):"$pc"},{"--set": "", "--monitor": True, "--clear": True}) # kwarg사용시 필요, --???시 True로 초기화됨
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        taint = Taint_function()
        
        def hook_stop(event): # 멈출때마다 monitor동작 구현
            global global_taint_progress
            taint_res = global_taint_progress['set_REG'] # 오염 시작 지점
            
            if args.location == "$pc":
                location = parse_address(args.location) # int값
            else:
                location = int(args.location,16)
                
            if check_location(location): #location범위 확인하는 함수
                
                # set 기능
                insns = [] # INSTRUCTION 클래스가 들어감
                opcodes_len = 0
                length = 1
                
                list_result_ds = cs_disassemble(location, length, skip=length * self.repeat_count, **kwargs) # DISASSEMBLY 핵심
                
                for insn in list_result_ds: # DISASSEMBLY 핵심
                    insns.append(insn)
                    opcodes_len = max(opcodes_len, len(insn.opcodes)) # ?
                
                show_opcodes = True
                insn = insns[0]
                dict_insn = {}
                dict_key = ['addr','opcode','location','inst','semantic']
                dict_insn['semantic'] = []
                
                insn_fmt = f"{{:{opcodes_len}o}}" if show_opcodes else "{}"
                text_insn = insn_fmt.format(insn)
                list_insn = list(filter(lambda x: x!='',text_insn.split(" "))) # ''는 리스트에서 필터링처리
                for i in range(len(list_insn)):
                    if i < 4:
                        dict_insn[dict_key[i]]=list_insn[i]
                    else:
                        list_insn[i] = list_insn[i].replace(',','')
                        dict_insn['semantic'].append(list_insn[i])
                        
                # 오염 여부 확인
                inst = dict_insn['inst']
                semantic = dict_insn['semantic']
                
                # 1) 데이터 로드 및 저장 명령어(MOV, LEA(미완))
                if inst == "mov":
                    if semantic[0] == taint_res:
                        global_taint_progress['total_taint'].append(dict_insn)
                    elif semantic[1] == taint_res:
                        taint_res = semantic[0]
                        global_taint_progress['total_taint'].append(dict_insn)
                
                # 2) 연산 명령어(ADD, SUB, MUL, DIV / AND, OR, XOR)
                if inst == "add" or inst == "sub" or inst == "mul" or inst == "div":
                    if semantic[0] == taint_res:
                        global_taint_progress['total_taint'].append(dict_insn)
                    elif semantic[1] == taint_res:
                        taint_res = semantic[0]
                        global_taint_progress['total_taint'].append(dict_insn)
                
                if inst == "and" or inst == "or" or inst =="xor":
                    if semantic[0] == taint_res:
                        global_taint_progress['total_taint'].append(dict_insn)
                    elif semantic[1] == taint_res:
                        taint_res = semantic[0]
                        global_taint_progress['total_taint'].append(dict_insn)
                
                # 3) 분기 및 점프 명령어(CMP / JMP, JE, JNE, JZ, JNZ)
                if inst == "cmp":
                    if semantic[0] == taint_res:
                        global_taint_progress['total_taint'].append(dict_insn)
                    elif semantic[1] == taint_res:
                        taint_res = semantic[0]
                        global_taint_progress['total_taint'].append(dict_insn)
                
                # 4) 메모리 접근 명령어(push, pop)
                
                # +) call명령어에 대한 매개변수(x86, x64에 따른 영향력 추가) 필요
            
            # 오염 명령어 출력
            for i in range(len(global_taint_progress['total_taint'])):
                _taint = global_taint_progress['total_taint'][i]
                _semantic = " ".join(_taint['semantic'])
                print(f"#{i} : {inst} {_semantic}")
            
            taint.finish_taint_progress() # Last
            
        # ---------
        
        # 1. module없을 경우 자동 설치
        import_or_install("capstone")
        
        # 2. args 값 가져오는 것
        args = kwargs["arguments"]
        set_flag = args.set
        monitor_flag = args.monitor
        clear_flag = args.clear
        list_flag = [monitor_flag, set_flag, clear_flag]
        
        # 3. check flag -> status
        list_status = list(check_flag(list_flag))
        # print(list_status)
        
        # 4. location값 설정
        if args.location == "$pc":
            location = parse_address(args.location) # int값
        else:
            location = int(args.location,16)
        
        # 3-1. location 검증
        if check_location(location): #location범위 확인하는 함수
            # 기록할 파일 존재여부 확인후 생성
            # "taint_progress"란 파일이 존재한다면 -> 진행사항 가져오기
            # 없다면 새로 생성후 frame구축
            
            taint.load_taint_progress()
            
            # 5. status 값에 따른 기능 수행
            # [monitor_flag, set_flag, clear_flag]
            if list_status[2] == "1":
                # clear 기능
                # => 값에 대한 초기화 기능
                # => 내부값을 유지할 방법이 없으니 "taint_progress"파일을 삭제후 다시 생성하여 초기화하는 방법
                taint.function_clear()
            
            if list_status[1] == "1":
                # set 기능
                insns = [] # INSTRUCTION 클래스가 들어감
                opcodes_len = 0
                length = 1
                list_result_ds = cs_disassemble(location, length, skip=length * self.repeat_count, **kwargs) # DISASSEMBLY 핵심
                
                taint.function_set(location, list_result_ds, set_flag)
                
                
            if list_status[0] == "1":
                # monitoring 기능
                
                # 현재 hook_stop함수가 등록되어있는지 확인하는 함수
                status = taint.confirm_register_function()
                
                if status == "on":
                    print("[*] 모니터링 상태는 on입니다.")
                    print("[*] 모니터링 종료를 원하신다면 off를 입력해주세요")
                    sel = input(">> ")
                    if sel == "off":
                        gdb.events.stop.disconnect(hook_stop)
                        print()
                        gef_print("[*] 상태가 off로 변경되었습니다.")
                    else:
                        gef_print("[!] 잘못된 입력입니다. 모니터링은 on상태입니다.")
                else:
                    # status : off 
                    print("[*] 모니터링 상태는 off입니다.")
                    print("[*] 모티너링 동작을 원한다면 on을 입력해주세요")
                    sel = input(">> ")
                    print()
                    if sel == "on":
                        gdb.events.stop.connect(hook_stop)
                        print()
                        gef_print("[*] 상태가 on으로 변경되었습니다.")
                    else:
                        gef_print("[!] 잘못된 입력입니다. 모니터링은 off상태입니다.")
                
                #gdb.execute("context")
            
        else:
            # code section 주소가 아닌 경우
            gef_print("[!] Code Section 범위의 주소입니다.")
            return
        
        
        return
    
        # 6. 쓰레드 백그라운드로 매번 확인후 $PC가 바뀌었을때 오염검사 진행
        # => 오염이 됬다면 GEF_PRINTR같은것으로 자동 호출
        # (+) 추가기능 : --monitor, --print, --clear같은 기능들은 주요 기능 실행 전에 여기서 체크후 기능실행
        
# 명령어 : clear용도
class clear(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "clear"
    #_syntax_  = f"{_cmdline_}"
    _syntax_ = f"{_cmdline_} [-h] [--show-opcodes] [--length LENGTH] [LOCATION]"

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        clear_screen()
        return

register_external_command(Taint_Reg())
register_external_command(clear())
