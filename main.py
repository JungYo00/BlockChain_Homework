import hashlib # SHA 256
from ecdsa import SigningKey,VerifyingKey, SECP256k1 # 서명, 서명검증
import inspect  # transaction 유효성 판정 시 faild일 때 몇 번째 line에서 발생했는지 알기 위해 사용
import pandas as pd  # 엑셀 data 처리(전처리)
import openpyxl # 엑셀 읽기

# ---------------------------------------- snapshot -----------------------------------
def snapshot_transactions():
    print('------------------------------------------------snapshot_transactions------------------------------------------------')
    for i in range(TX_idx):
        print('transaction: ' + Transactions_Txid[i].hex() + ', '  +  'validity check: ' +  Transactions_Valid[i])
    print('---------------------------------------------------------------------------------------------------------------------')
    print('\n\n')

def snapshot_utxoset():
    print('--------------------------------------------------------------------------------snapshot_utxoset--------------------------------------------------------------------------------')
    IDX = 0
    for i in range(len(UTXO)):
        if UTXO['input_ptxid'][i] != None:
            print('utxo' + str(IDX) + ': ' + str(UTXO['input_ptxid'][i]) + ', ' + str(int(UTXO['input_output index'][i])) + ', ' + str(int(UTXO['input_amount'][i])) + ', ' + str(UTXO['input_locking script'][i]))
            IDX = IDX + 1
    print('-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
    print('\n\n')
# -------------------------------------------------------------------------------------------

def Get_TXID(C_Tx_idx, C_Output_cnt):
    R_T = Raw_Transaction(C_Tx_idx, C_Output_cnt)
    R_T_txid = hashlib.sha256(R_T.encode()).digest()
    return R_T_txid

# locking script에 제시할 signature 생성
# locking script 비우고 전체 transcation에 대해 sha256 적용한 결과에 서명
def Raw_Transaction_HASH_For_SIG(C_Tx_idx, C_Output_cnt):
    raw_transaction = (str(UTXO["input_ptxid"][C_Tx_idx]) + str(int(UTXO["input_output index"][C_Tx_idx]))
                       + str(float(UTXO["input_amount"][C_Tx_idx])) + str(UTXO["input_locking script"][C_Tx_idx]))

    for i in range(C_Output_cnt):
        A = 'output_index'
        B = 'output_amount'
        C = 'output_locking script'
        raw_transaction = raw_transaction + str(int(TX[A + str(i)][C_Tx_idx])) + str(float(TX[B + str(i)][C_Tx_idx])) + str(TX[C + str(i)][C_Tx_idx])

    raw_transaction = raw_transaction.replace(" ", "")  # 공백 제거

    # 서명 대상 raw_trasnaction
    raw_transaction_hash = hashlib.sha256(raw_transaction.encode()).digest()

    return raw_transaction_hash


def Raw_Transaction(C_Tx_idx, C_Output_cnt):
    raw_transaction = (str(UTXO["input_ptxid"][C_Tx_idx]) + str(UTXO["input_output index"][C_Tx_idx])
                       + str(UTXO["input_amount"][C_Tx_idx]) + str(UTXO["input_locking script"][C_Tx_idx])
                       + str(TX["input_unlocking script"][C_Tx_idx]))
    
    for i in range(C_Output_cnt):
        A = 'output_index'
        B = 'output_amount'
        C = 'output_locking script'
        raw_transaction = raw_transaction + str(TX[A + str(i)][C_Tx_idx]) + str(TX[B + str(i)][C_Tx_idx]) + str(TX[C + str(i)][C_Tx_idx])

    raw_transaction = raw_transaction.replace(" ", "")  # 공백 제거
    return raw_transaction


#-------------------------------------------------- OP CODE 정의-----------------------------------------------------------
def DUP():
    data = stack.pop()
    stack.append(data)
    stack.append(data)

def HASH():
    data = stack.pop()
    hash_object = hashlib.sha256()
    hash_object.update(data.encode())
    hash_value = hash_object.hexdigest()
    stack.append(hash_value)

def EQUAL():
    data1 = stack.pop()
    data2 = stack.pop()
    if data1 == data2:
        stack.append(True)
    else:
        stack.append(False)

def EQUALVERIFY():
    global Transaction_Valid, Error_Line
    data1 = stack.pop()
    data2 = stack.pop()
    if data1 != data2:
        Transaction_Valid = False
        Error_Line = inspect.currentframe().f_lineno

def CHECKSIG():
    Pub_K = stack.pop()
    SIG = stack.pop()
    raw_tx = Raw_Transaction_HASH_For_SIG(TX_idx, Output_cnt)

    # 서명 검증을 위한 올바른 형태로 바꾸기
    Pub_K = VerifyingKey.from_string(bytes.fromhex(Pub_K), curve=SECP256k1)
    SIG = bytes.fromhex(SIG)

    try:
        if Pub_K.verify(SIG, raw_tx):  # 성공 시 True 반환
            stack.append(True)
    except:
        stack.append(False)

def CHECKSIGVERIFY():
    global Transaction_Valid, Error_Line
    CHECKSIG()
    BOOL = stack.pop()
    if not BOOL:
        Transaction_Valid = False
        Error_Line = inspect.currentframe().f_lineno

def CHECKMULTISIG():
    Message = Raw_Transaction_HASH_For_SIG(TX_idx, Output_cnt)
    N = int(stack.pop())
    publicKeys = []

    for i in range(N):
        PuB_K = stack.pop()
        PuB_K = VerifyingKey.from_string(bytes.fromhex(PuB_K), curve=SECP256k1)
        publicKeys.append(PuB_K)

    M = int(stack.pop())
    signatures = []

    for i in range(M):
        SiG = stack.pop()
        SiG = bytes.fromhex(SiG)
        signatures.append(SiG)

    # 서명 검증
    VALID_SIG_CNT = 0
    for i in range(M):
        for j in range(N):
            try:
                if publicKeys[j].verify(signatures[i], Message):
                    VALID_SIG_CNT = VALID_SIG_CNT + 1
            except:
                pass

    if VALID_SIG_CNT == M:
        stack.append(True)
    else:
        stack.append(False)

def CHECKMULTISIGVERIFY():
    global Transaction_Valid, Error_Line
    CHECKMULTISIG()
    BOOL = stack.pop()
    if not BOOL:
        Transaction_Valid = False
        Error_Line = inspect.currentframe().f_lineno

def IF():
    global if_value
    Condition_Value = stack.pop()
    if Condition_Value == 'False' or Condition_Value == '0':
        Condition_Value = False
    else:
        Condition_Value = True

    if Condition_Value:
        if_value = True
    else:
        if_value = False


def ELSE():
    global if_value
    if if_value:
        if_value = False
    else:
        if_value = True


def ENDIF():
    global if_value
    if_value = True


def CHECKFINALRESULT():
    if len(stack) == 1 and stack[0] == True:
        return True
    else:
        Transaction_Valid = False
        Error_Line = inspect.currentframe().f_lineno
        return False
# ------------------------------------------------------------------------------------------------------------------------------------

# transaction 유효성 판단 후 최종 결과 출력
def TX_Result():
    txid = Get_TXID(TX_idx, Output_cnt)
    print('transaction:', txid.hex())
    print('   input')
    print('       ptxid:', UTXO["input_ptxid"][TX_idx])
    print('       output index:', UTXO["input_output index"][TX_idx])
    print('       amount:', UTXO["input_amount"][TX_idx])
    print('       locking script:', UTXO["input_locking script"][TX_idx])
    print('       unlocking script:', TX["input_unlocking script"][TX_idx])
    print('   output')
    for a in range(Output_cnt):
        A = 'output_index'
        B = 'output_amount'
        C = 'output_locking script'
        print('       index' + str(a) + ':', int(TX[A + str(a)][TX_idx]))
        print('       amount' + str(a) + ':', TX[B + str(a)][TX_idx])
        print('       lockingscript' + str(a) + ':', TX[C + str(a)][TX_idx])

    if CHECKFINALRESULT():
        print("validity check: passed")
        Transactions_Valid.append('passed')
    else:
        print("validity check: failed")
        print("               failed at " + str(Error_Line) + "line")
        Transactions_Valid.append('failed')
    print()
    print()
    Transactions_Txid.append(txid)


# -------------------------------------------------------------------- main 함수 ------------------------------------------------------------------------------
TX = pd.read_excel("transactions.xlsx",)
UTXO = pd.read_excel("UTXOes.xlsx")
opcode_functions = {
    'DUP': DUP,
    'HASH': HASH,
    'EQUAL': EQUAL,
    'EQUALVERIFY': EQUALVERIFY,
    'CHECKSIG': CHECKSIG,
    'CHECKSIGVERIFY': CHECKSIGVERIFY,
    'CHECKMULTISIG': CHECKMULTISIG,
    'CHECKMULTISIGVERIFY': CHECKMULTISIGVERIFY,
    'IF': IF
}

# snapshot transactions에 대한 리스트
Transactions_Txid = []
Transactions_Valid = []

if_value = True
for TX_idx in range(len(UTXO["input_ptxid"])):
    if_value = True
    P2SH_Valid = False
    Transaction_Valid = True
    Error_Line = -1
    # TX_idx - 현재 처리하고 있는 trasnaction의 index
    # Output_cnt - 현재 처리하고 있는 trasnaction의 output 갯수
    Output_cnt = 1
    if not pd.isna(TX["output_index1"][TX_idx]):
        Output_cnt = 2
    if not pd.isna(TX["output_index2"][TX_idx]):
        Output_cnt = 3

    # 1. 금액 검증
    spend_amount = 0 # 현재 처리하고 있는 transcation에 명시된 output amount의 총합
    a = 'output_amount'
    for i in range(Output_cnt):
        spend_amount = spend_amount + TX[a + str(i)][TX_idx]


    if spend_amount > UTXO["input_amount"][TX_idx]:
         Error_Line = inspect.currentframe().f_lineno
         Transaction_Valid = False


    # 2.script 검증
    Locking_Script = UTXO["input_locking script"][TX_idx].split()

    # locking script가 P2SH 형태인 것 감지
    Unlocking_Script_Reduce_FirstNum = []
    if(len(Locking_Script) == 4 and Locking_Script[0] == 'DUP' and Locking_Script[1] == 'HASH' and len(Locking_Script[2]) == 64 and Locking_Script[3] == 'EQUALVERIFY'):
        US = TX["input_unlocking script"][TX_idx]
        US = US.split()
        First_Number = int(US[0])

        Unlocking_Script_Reduce_FirstNum = US[1:]
        Unlocking_Script_Reduce_FirstNum = " ".join(Unlocking_Script_Reduce_FirstNum)

        US = US[First_Number+1:]
        US = " ".join(US)
        US = US.replace(" ", "")
        hash_object = hashlib.sha256()
        hash_object.update(US.encode())
        US_HASH = hash_object.hexdigest()

        if US_HASH == Locking_Script[2]:
            P2SH_Valid = True


    if P2SH_Valid:
        full_script = str(Unlocking_Script_Reduce_FirstNum)
        full_script = full_script.split()
    else:
        full_script = str(TX["input_unlocking script"][TX_idx]) + ' ' + str(UTXO["input_locking script"][TX_idx])
        full_script = full_script.split()

    stack = []
    for script in full_script:
        if script == 'ELSE':
            ELSE()
        elif script == 'ENDIF':
            ENDIF()
        elif not if_value:
            continue
        elif script in opcode_functions:
            opcode_functions[script]()
        else:
            stack.append(script)
        if not Transaction_Valid:
            break

    
    # trnasction 처리 후 최종 결과 출력
    TX_Result()

    # 현재 transcation 유효성 확인 후 유효하면 사용한 UTXO 제거 후 생성된 UTXO 추가
    if CHECKFINALRESULT():
        UTXO.drop(TX_idx).reset_index(drop=True, inplace=True)
        UTXO.loc[TX_idx] = [None] * 4  # 모든 열에 None 값을 입력

        # UTXO 추가
        TXID = Get_TXID(TX_idx, Output_cnt).hex()
        A = 'output_index'
        B = 'output_amount'
        C = 'output_locking script'
        for LENGTH in range(Output_cnt):
            # 추가할 데이터
            new_row = {
                "input_ptxid": TXID,
                "input_output index": TX[A + str(LENGTH)][TX_idx],
                "input_amount": TX[B + str(LENGTH)][TX_idx],
                "input_locking script": TX[C + str(LENGTH)][TX_idx],
            }
            UTXO.loc[len(UTXO)] = new_row

    # 지금까지 검증한 transaction들의 정보
    if TX_idx == 6: # -1 <- 원하는 값 넣고 확인
        snapshot_transactions()

    # 현재 시점의 UTXO 정보
    if TX_idx == 6: # -1 <- 원하는 값 넣고 확인
        snapshot_utxoset()


