<?php
#expiration date of jwt token
$GLOBALS['expired_date']='+6 month';

#Bakong link account table
$GLOBALS['tblInit']='tblinit';
$GLOBALS['tblLinkAcc']='tbllinkaccount';
$GLOBALS['tblUnlink']='tblunlink';
$GLOBALS['tblTrx']='tbltransaction';


#T24 Gateway
$GLOBALS['T24GetAccountDetails'] = 'http://10.195.101.21:8111/api/v1/bakonglinked/getaccountdetail';
$GLOBALS['T24GetAccountTransaction'] = 'http://10.195.101.21:8111/api/v1/bakonglinked/gettransactionhistory';
$GLOBALS['T24DoTransaction'] = 'http://10.195.101.21:8111/api/v1/bakonglinked/transfer';


#Encryption api
$GLOBALS['encryptor']='http://10.195.55.18:8082/encrypt';

#API MB
$GLOBALS['userAuthenticator']='http://10.195.55.18:8082/api/v1/authenticate-user';
$GLOBALS['initOTP']='http://10.195.55.18:8082/api/v1/init-send-otp';
$GLOBALS['verifyOTP']='http://10.195.55.18:8082/api/v1/verify-otp';


#fixed variable for requesting MB
$GLOBALS['bankCode']='970467';
$GLOBALS['clientCretKey']='27f66797cbb4493fb1c2d6112277376a';
$GLOBALS['chanel']='6015';
$GLOBALS['smsformat']='OTP active bakong: #SMSVALUE';
$GLOBALS['expireOTP']=3;
$GLOBALS['ip']='10.195.55.18';


#user password access MB
$GLOBALS['username']='vnpay_bidc';
$GLOBALS['password']='vnpay_bidc@2023';


#folder for log file
$GLOBALS['folderLog']='../log/';


#Fixed NBC Clearing Account
$GLOBALS['NBCAccount']='953700000448';

#Prefix TXNREFERENCECODE
$GLOBALS['prefixTrxRef']='BKO';
$GLOBALS['transHash']='xxxxxxxx';

$GLOBALS['loginType']='USER_PWD';
$GLOBALS['transactionType']='CASA_TO_WALLET';


?>