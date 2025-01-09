1.使用tls 1.3
2.寫一個server可以同時接受多個不同的client連上來，並上傳單一檔案
3.寫一個client上傳檔案，且可以同時執行多次，上傳不同檔案
4. client 可以指定邏輯目錄，檔名，例如-p 2024/05/01 -f test.txt
5. server端啟用時需指定絕對目錄，例如/myfiles，當client放上來時就會變成/myfiles+/2025/05/01/+test.txt
6. server需回應是否上傳成功
7.client需等待server上傳成功，或是就是失敗信息
8.client上傳，預設不覆蓋已存在檔案，但可指定是否覆蓋 -r
9. server預設不覆蓋，除非client指定，並且判斷是否檔案已經存在
10.server上傳中用臨時檔名_tmp.$filename存放，等上傳完畢，才將檔案改名為指定檔案
11.client需要用到server.crt上傳(tls 1.3)
12. server/client都需要詳細的log顯示
13. 確保tls 1.3能正常的SSL/TLS handshake
14. 確保檔案能正常上傳
15. 加上參數"DEBUG"作為更詳細的紀錄
16. 先顯示整個程式架構及檔案目錄
