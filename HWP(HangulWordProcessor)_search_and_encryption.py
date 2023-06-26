import tkinter as tk
import os
from tkinter import filedialog
import threading
import time
import olefile
import pymysql
from tkinter import messagebox
from cryptography.fernet import Fernet
import re

def find_hwp_files(root_directory): # 선택한 경로에서 .hwp or .hwpx 확장자 가진 파일을 찾는 함수
    
    hwp_files = []

    #사전에 설정된 문자열 검색
    conn = pymysql.connect(host='127.0.0.1', user='root', password='root', db='search', charset='utf8') #DB 접속
    cur = conn.cursor()             #DB에서 쿼리를 생성하고 결과를 가져오는 역할
    cur.execute("SELECT * FROM search_table")           #쿼리문 생성(search_table에 있는 모든 행과 열 선택)
    rows = cur.fetchall()                               #쿼리문의 실행 결과인 모든 행을 가져와 rows 변수에 저장
    search_content = []      #찾으려는 문자열 DB에서 해당 문자열을 가져옴.
    for row in rows:
        search_content.append(row[0])  # 원하는 리스트에 데이터 추가
    conn.close()

    for foldername, subfolders, filenames in os.walk(root_directory):   # 디레터리를 순회하면서 디렉터리 구조를 반환
        for filename in filenames: # 파일 이름들을 검사
            if filename.endswith('.hwp') or filename.endswith('.hwpx'):  # 확장자가 hwp, hwpx 인경우
                file_path = os.path.join(foldername, filename) # 경로 생성
                try:
                    check_file_count = 0 #목록에 중복으로 추가되지 않게 예방하는 변수 
                    f = olefile.OleFileIO(file_path)            #olefile로 한글파일 열기
                    encoded_text = f.openstream('PrvText').read()       #PrvText 스트림 안의 내용 읽기
                    content = encoded_text.decode('UTF-16')             #인코딩된 텍스트를 UTF-16으로 디코딩

                    for keyword in search_content:
                        if keyword in content: # 특정 단어가 포함되어 있으면
                            hwp_files.append(file_path) # 리스트에 경로 추가
                            check_file_count = 1
                            break
                    
                    if find_personal_info(content) and (check_file_count==0) :
                        hwp_files.append(file_path) # 리스트에 경로 추가 

                except (UnicodeError, IOError) :                     # 예외처리 - utf-16으로 읽을 수 없는 파일은 건너뛴다
                    pass

    return hwp_files

def find_personal_info(text):
    personal_info = []
    
    # 주민등록번호 추출
    jumin_regex = r"\d{6}-"  # 주민등록번호 패턴 정규 표현식
    jumin_matches = re.findall(jumin_regex, text)  # 패턴과 일치하는 모든 주민등록번호 찾기
    personal_info.extend(jumin_matches)  # 주민등록번호 결과를 personal_info 리스트에 추가
    
    # 전화번호 추출
    phone_regex = r"\d{2,3}-\d{3,4}-\d{4}"  # 전화번호 패턴 정규 표현식
    phone_matches = re.findall(phone_regex, text)  # 패턴과 일치하는 모든 전화번호 찾기
    personal_info.extend(phone_matches)  # 전화번호 결과를 personal_info 리스트에 추가
    
    #계좌번호 추출
    account_regex = r"\d{3,6}-\d{3,6}-\d{3,6}"  # 전화번호 패턴 정규 표현식
    account_matches = re.findall(account_regex, text)  # 패턴과 일치하는 모든 전화번호 찾기
    personal_info.extend(account_matches)  # 전화번호 결과를 personal_info 리스트에 추가      

    if len(personal_info)==0 : 
        return False
    else : 
        return True


def search_hwp_files(): #  검색 및 결과 표시 함수
    start_time=time.time() # 함수 실행 시작 시간 저장
    search_button.config(state=tk.DISABLED) # 검색 버튼 비활성화
    instructions.config(text='탐색 중...')  # 안내문 변경

    hwp_files = [] # 결과 저장 리스트
    if selected_directory.get() != "No folder selected":  # 폴더가 선택된 경우
        hwp_files = find_hwp_files(selected_directory.get()) # 선택한 폴더에서 .hwp 파일 검색
    else: # 폴더가 선택 되지 않은 경우
        drives = ['C:/Users/', 'D:/'] # 검색할 드라이브 목록  
        for drive in drives: # 드라이브 목록 순회
            hwp_files.extend(find_hwp_files(drive)) # 각 드라이브에서 .hwp .hwpx 파일 검색 및 결과 리스트 추가

    results.delete(0, tk.END) # 결과 리스트 초기화
    count = 0
    for file_path in hwp_files: # 드라이브 목록 순회
        results.insert(tk.END, file_path) # 각 드라이브에서 .hwp 파일 리스트에 추가
        count += 1

    end_time = time.time() # 함수 실행 종료 시간 저장

    instructions.config(text=f'검색된 파일 개수: {count}\n소요 시간: {end_time - start_time:.2f}초\n폴더를 선택하고 검색 버튼을 클릭하여 .hwp 파일을 찾거나 컴퓨터 전체를 검색합니다\n검사 폴더 : %s' % selected_directory.get()) #검색된 파일 개수, 소요 시간과 검사한 폴더 출력
    search_button.config(state=tk.NORMAL) # 버튼활성화

def start_search(): # 멀티스레딩을 사용한 검색 시작
    search_thread = threading.Thread(target=search_hwp_files) # 새로운 스레드 생성
    search_thread.start() # 스레드 시작

def open_file(event): # 선택한 파일을 열어주는 함수
    selected_file = results.get(results.curselection()) # 선택한 파일 경로 가져오기
    #messagebox.showinfo("선택한 파일 경로", selected_file) # 선택한 파일 경로를 메시지 박스로 표시
    create_file_options(selected_file) # 선택한 파일을 암호화 또는 복호화할 수 있는 창 생성


def load_key():             #키를 불러오는 함수
    return open("key.key", "rb").read()     

def create_file_options(filename):          #파일을 암호화하는 함수
    if not os.path.exists("key.key"):       #해당 키가 없으면 키를 만듦
        generate_key()

    options_window = tk.Toplevel(root) # 새로운 창 생성
    options_window.title("파일 암호화")
    options_window.geometry("250x80")
    options_window.resizable(False, False)  # 크기 고정

    question_label = tk.Label(options_window, text="해당 파일을 암호화하시겠습니까?")
    question_label.pack(pady=10)  # 위 아래로 여백 추가

    button_frame = tk.Frame(options_window)  # 버튼을 담을 프레임 생성
    button_frame.pack()

    yes_button = tk.Button(button_frame, text="네", command=lambda: encrypt_file(filename, options_window))     #해당 파일을 암호화
    yes_button.pack(side=tk.LEFT, padx=10)

    no_button = tk.Button(button_frame, text="아니오", command=options_window.destroy)                  #취소
    no_button.pack(side=tk.LEFT, padx=10)

    # 중앙 정렬
    options_window.update_idletasks()
    window_width = options_window.winfo_width()
    window_height = options_window.winfo_height()
    screen_width = options_window.winfo_screenwidth()
    screen_height = options_window.winfo_screenheight()
    x = int((screen_width / 2) - (window_width / 2))
    y = int((screen_height / 2) - (window_height / 2))
    options_window.geometry(f"+{x}+{y}")

    
def encrypt_file(filename, options_window):             #파일 암호화 함수
    options_window.destroy() # 파일 옵션 창 닫기
    key = load_key()                    #키를 불러움
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)
    messagebox.showinfo("암호화 완료", "파일이 성공적으로 암호화되었습니다.")


def select_folder(): # 폴더 선택하ㅇ는 함수 정의
    folder = filedialog.askdirectory() # 폴더 선택 대화 상자 열기
    if folder: # 사용자가 폴더를 선택한 경우
        selected_directory.set(folder) # selected_directory StringVar 변수에 선택한 폴더의 경로를 설정합니다
        instructions.config(text='폴더를 선택하고 검색 버튼을 클릭하여 .hwp 파일을 찾거나 컴퓨터 전체를 검색합니다\n %s' % selected_directory.get())

def setting_string():               #문자열을 추가, 삭제하는 함수 정의
    conn = pymysql.connect(host='127.0.0.1', user='root', password='root', db='search', charset='utf8')      #DB 접속
    cur = conn.cursor()                                  #DB에서 쿼리를 생성하고 결과를 가져오는 역할
    cur.execute("SELECT * FROM search_table")              #테이블에 있는 요소를 조회하기 위한 쿼리문
    rows = cur.fetchall()                                   #해당 요소들 저장

    def delete_string():                                #저장되어있는 문자열 삭제 함수 정의
        selected_index = listbox.curselection()         #리스트박스에 있는 문자열 선택
        if selected_index:                  
            selected_string = listbox.get(selected_index)       
            cur.execute("DELETE FROM search_table WHERE data=%s", (selected_string,))       #해당 요소 삭제 쿼리문
            conn.commit()                                                                   #DB 적용
            listbox.delete(selected_index)

    def add_string():                               #사용자가 입력한 문자열 저장 함수 정의
        new_string = entry.get()                    #사용자가 문자를 입력할때 
        if new_string:
            cur.execute("INSERT INTO search_table (data) VALUES (%s)", (new_string,))       #해당 문자 추가 쿼리문
            conn.commit()                                                                   #DB저장
            listbox.insert(tk.END, new_string)                                              #리스트 박스에 추가
            entry.delete(0, tk.END)

    setting_window = tk.Toplevel(root)                      #문자열 설정 창 생성
    setting_window.title('Stored Strings')                  #문자열 설정 창 이름    

    listbox = tk.Listbox(setting_window, width=50, height=20)       #DB에 저장된 문자열 출력을 위한 리스트 박스 생성
    listbox.pack(fill=tk.BOTH, expand=True)

    for row in rows:
        string = row[0]                                 #DB에 저장된 문자열을 리스트 박스에 추가 
        listbox.insert(tk.END, string)

    delete_button = tk.Button(setting_window, text="삭제", command=delete_string)       # 문자열 삭제 버튼
    delete_button.pack(pady=10)

    entry = tk.Entry(setting_window)            #문자열 추가 입력 란
    entry.pack(pady=10)

    add_button = tk.Button(setting_window, text="추가", command=add_string)         #문자열 추가 버튼
    add_button.pack(pady=10)

def on_closing():           #프로그램 종료 시 확인 창 생성. DB 종료기능 추가
    if messagebox.askokcancel("확인", "애플리케이션을 종료하시겠습니까?"):
        conn = pymysql.connect(host='127.0.0.1', user='root', password='root', db='search', charset='utf8')     #DB 접속
        cur = conn.cursor()          #DB에서 쿼리를 생성하고 결과를 가져오는 역할
        cur.close()             #커서 종료
        conn.close()            #DB 종료
        root.destroy()

def generate_key():                     #키를 만드는 함수
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def select_file_to_decrypt():                       #복호화 파일 선택하는 함수
    filename = filedialog.askopenfilename(title="복호화 파일 선택")     
    key = load_key()
    decrypt_file(filename, key)         #복호화 함수 실행

def decrypt_file(filename, key):        #복호화 함수
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    messagebox.showinfo("복호화 완료", "파일이 성공적으로 복호화되었습니다.")

def check_decrypt_password():
    conn = pymysql.connect(host='127.0.0.1', user='root', password='root', db='search', charset='utf8')      #DB 접속
    cur = conn.cursor()                                  #DB에서 쿼리를 생성하고 결과를 가져오는 역할
    cur.execute("SELECT * FROM password_table")              #테이블에 있는 요소를 조회하기 위한 쿼리문
    row = cur.fetchone()

    current_password = row[0]

    password_check_window = tk.Toplevel(root)                      #문자열 설정 창 생성
    password_check_window.title('Password Check')
    password_check_window.geometry("300x100")

    def check_d_password() :
        password_check_window.withdraw() 
        input_password = entry_current_password.get()
        if input_password == current_password :
            messagebox.showinfo("알림", "비밀번호가 일치합니다.")
            create_decrypt_window()
        else:
            messagebox.showwarning("경고", "비밀번호가 일치하지 않습니다.")

    def handle_enter(event):  # 엔터 키를 눌렀을 때 처리하는 함수
        check_d_password()

    label_current_password = tk.Label(password_check_window, text="기존 비밀번호:")
    label_current_password.pack()
    entry_current_password = tk.Entry(password_check_window, show="*")
    entry_current_password.pack()
    entry_current_password.bind("<Return>", handle_enter)  # Entry 위젯에 엔터 키 이벤트 바인딩
    # 확인 버튼
    button_confirm = tk.Button(password_check_window, text="확인", command=check_d_password)
    button_confirm.pack()


def create_decrypt_window():                #복호화하는 창 생성
    if not os.path.exists("key.key"):
        generate_key()
    decrypt_window = tk.Toplevel(root) # 새로운 창 생성
    decrypt_window.title("파일 복호화")
    decrypt_window.geometry("250x80")
    decrypt_window.resizable(False, False)  # 크기 고정

    decrypt_button = tk.Button(decrypt_window, text="복호화 파일 선택", command=select_file_to_decrypt)
    decrypt_button.pack(pady=20)  # 버튼 아래 여백 추가


def setting_password() :
    conn = pymysql.connect(host='127.0.0.1', user='root', password='root', db='search', charset='utf8')      #DB 접속
    cur = conn.cursor()                                  #DB에서 쿼리를 생성하고 결과를 가져오는 역할
    cur.execute("SELECT * FROM password_table")              #테이블에 있는 요소를 조회하기 위한 쿼리문
    row = cur.fetchone()
    current_password = row[0]

    def check_password() :
        input_password = entry_current_password.get()
        if input_password == current_password :
            messagebox.showinfo("알림", "비밀번호가 일치합니다.")
            password_change_window = tk.Toplevel(password_setting_window)  # 새로운 비밀번호 입력 창 생성
            password_change_window.title("새로운 비밀번호 입력")
            password_change_window.geometry("300x100")
        
            password_setting_window.withdraw()  # password_setting_window를 숨김

            def change_password() : 
                new_password = entry_new_password.get()

                cur.execute("DELETE FROM password_table WHERE password=%s", (current_password,))       #해당 요소 삭제 쿼리문
                cur.execute("INSERT INTO password_table (password) VALUES (%s)", (new_password,))
                conn.commit()
                messagebox.showinfo("알림", "비밀번호 변경 완료")
            
        
            label_new_password = tk.Label(password_change_window, text="새로운 비밀번호:")
            label_new_password.pack()
            entry_new_password = tk.Entry(password_change_window, show="*")  # 비밀번호를 입력할 때 보이지 않도록 함
            entry_new_password.pack()
            entry_new_password.bind()
            button_change_password = tk.Button(password_change_window, text="비밀번호 변경", command=change_password)
            button_change_password.pack()
            entry_new_password.bind("<Return>", lambda event: button_change_password.invoke())  # Entry 위젯에 엔터 키 이벤트 바인딩
    
        else:
            messagebox.showwarning("경고", "비밀번호가 일치하지 않습니다.")

    def handle_enter(event):  # 엔터 키를 눌렀을 때 처리하는 함수
        check_password()

    password_setting_window = tk.Toplevel(root)                      #문자열 설정 창 생성
    password_setting_window.title('Password Setting')
    password_setting_window.geometry("300x100")

    label_current_password = tk.Label(password_setting_window, text="기존 비밀번호:")
    label_current_password.pack()
    entry_current_password = tk.Entry(password_setting_window)
    entry_current_password.pack()
    entry_current_password.bind("<Return>", handle_enter)  # Entry 위젯에 엔터 키 이벤트 바인딩
    # 확인 버튼
    button_confirm = tk.Button(password_setting_window, text="확인", command=check_password)
    button_confirm.pack()




# Create the GUI
root = tk.Tk() # 애플리케이션의 루트 창을 생성
root.title('HWP File Finder') # 루트 창의 제목 설정

frame = tk.Frame(root) # 루트 창 내에 프레임 생성
frame.pack(padx=10, pady=10) # 패딩을 넣어 프레임 추가


selected_directory = tk.StringVar() # 선택한 디렉터리 저장할 stringvar를 생성
selected_directory.set("No folder selected") # 변수의 기본값 설정

instructions = tk.Label(frame, text='폴더를 선택하고 검색 버튼을 클릭하여 .hwp 파일을 찾거나 컴퓨터 전체를 검색합니다\n %s' % selected_directory.get())
instructions.pack() # 위의 문자열을 표시하는 라벨 추가

search_button = tk.Button(frame, text='검색', command=start_search) # 검색 버튼을 생성하고 클릭 시 strt_search 함수 할당
search_button.pack(pady=10) # 검색 버튼을 프레임에 세로 패딩으로 추가

results_label = tk.Label(frame, text='결과') # 결과 텍스트 표시
results_label.pack() # 프레임에 라벨 추가

results = tk.Listbox(frame, width=120, height=40) # 검색 결과 표시 목록 
results.pack() # 리스트박스를 프레임에 추가
results.bind('<Double-1>', open_file) # 더블클릭 이벤트를 open_file 함수에 바인딩

# Add a menu
menu = tk.Menu(root) # 메뉴 생성
root.config(menu=menu) # 메뉴 루트창에 할당


settingmenu = tk.Menu(menu) # 파일 메뉴에 대한 하위 메뉴 생성
menu.add_cascade(label="Setting(S)", menu=settingmenu) # 메인 메뉴에 설정 하위 메뉴 추가
settingmenu.add_command(label="폴더 열기", command=select_folder) # 폴더 열기 옵션 추가
settingmenu.add_command(label="탐색 설정", command=setting_string) #문자열 설정 기능 추가
settingmenu.add_command(label="암호 설정", command=setting_password) #문자열 설정 기능 추가


decryptmenu = tk.Menu(menu) # 파일 메뉴에 대한 하위 메뉴 생성
menu.add_cascade(label="Decrypt(D)", menu=decryptmenu) # 메인 메뉴에 설정 하위 메뉴 추가
decryptmenu.add_command(label="복호화", command=check_decrypt_password) # 폴더 열기 옵션 추가


root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop() # 메인루프 실행
