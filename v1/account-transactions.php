<?php
require '../config/config.php';
include '../config/database.php';
include '../file/filelog.php';
include '../helper/dbconnection.php';

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("App-Name: BAKONG");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

$appName ='';
$contentType='';
$ALLHeaders = getallheaders();
if (isset($ALLHeaders['App-Name'])){
    $appName = $ALLHeaders['App-Name'];
}
if(isset($ALLHeaders['Content-Type'])){
    $contentType=$ALLHeaders['Content-Type'];
}

if($appName==='BAKONG' and $contentType==='application/json'){

$data=json_decode(file_get_contents("php://input"));
$db=new DBConnection();
$bakonglog=new Log();

$headers = null;
if (isset($_SERVER['Authorization'])) {
    $headers = trim($_SERVER["Authorization"]);
}
else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { 
    $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
} elseif (function_exists('apache_request_headers')) {
    $requestHeaders = apache_request_headers();
    $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
    if (isset($requestHeaders['Authorization'])) {
        $headers = trim($requestHeaders['Authorization']);
    }
}
if (!empty($headers)) {
    if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
        $matches[1];
        $jwt = $matches[1];
    }
}

if(isset($jwt)){
    $cmd_token=$db->getToken_withLinkacc($jwt,$tblInit,$tblLinkAcc);
    if($cmd_token->rowCount()){
        $row=$cmd_token->fetch(PDO::FETCH_ASSOC);

        $bakonglog->bakonglog($row['loginPhoneNumber'],'account-transaction',json_encode($data),'Request log data',$folderLog);

        $key_num = $row['key_num'];
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];

        $expiration = (json_decode($payload)->exp);
        $now = date_create('now')->format('Y-m-d H:i:s');
        $dateTimeNow = new DateTime($now);
        $dateTimeStamp = $dateTimeNow->getTimestamp();

        $secret = $key_num;
        $base64UrlHeader = base64_encode($header);
        $base64UrlPayload = base64_encode($payload);
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secret, true);
        $base64UrlSignature = base64_encode($signature);
        $signatureValid = ($base64UrlSignature === $signatureProvided);

        if($dateTimeStamp>$expiration){
            $JSON='{
                "status":{
                    "code":1,
                    "errorCode":5,
                    "errorMessage":"Your Session has expired."
                },
                "data":null
            }';

            $bakonglog->bakonglog($row['loginPhoneNumber'],'account-transaction',$JSON,'Response log data',$folderLog);
            echo $JSON;
        }else{
            if(empty($signatureValid)){
                $JSON='{
                    "status":{
                        "code":1,
                        "errorCode":7,
                        "errorMessage":"Token is invalid."
                    },
                    "data":null
                }';

                $bakonglog->bakonglog($row['loginPhoneNumber'],'account-transaction',$JSON,'Response log data',$folderLog);
                echo $JSON;               
            }else{
                if(empty($data->accNumber) and empty($data->page) and empty($data->size)){
                    $JSON='{
                        "status":{
                            "code":1,
                            "errorCode":6,
                            "errorMessage":"Missing mandatory element."             
                        },
                        "data":null
                    }';

                    $bakonglog->bakonglog($row['loginPhoneNumber'],'account-transaction',$JSON,'Response log data',$folderLog);
                    echo $JSON;
                }else{
                    if($row['account']==$data->accNumber){
                        $login=$row['loginPhoneNumber'];

                        $transactions = $db->getAccountTransction($data->accNumber,$data->size,$tblTrx);
                        if($transactions->rowCount()){
                            $totalElement=$transactions->rowCount();
                            $transantion_element=$transactions->fetch(PDO::FETCH_ASSOC);

                            $type=$transantion_element['transType'];
                            $sourceAcc=$transantion_element['fromAcc'];
                            $destinationAcc=$transantion_element['toAcc'];
                            $amount=$transantion_element['amount'];
                            $ccy=$transantion_element['currency'];
                            $decs=$transantion_element['desc'];                  
                            $cdtDbtInd=$transantion_element['dbtCdt'];
                            $transactionId=$transantion_element['transId'];
                            $status=$transantion_element['status'];
                            $miliSecond=$transantion_element['datetimeinmilisecond'];

                            if($cdtDbtInd==='Debit'){
                                $destinationAcc=$row['bakongAccId'];
                                $cdtDbtInd = 'D';
                            }

                            $JSON='{
                                "status":{
                                    "code":0,
                                    "errorCode":null,
                                    "errorMessage":null
                                },
                                "data":{
                                    "transactions":[
                                        {
                                            "type":"'.$type.'",
                                            "sourceAcc":"'.$sourceAcc.'",
                                            "destinationAcc":"'.$destinationAcc.'",
                                            "amount":'.$amount.',
                                            "ccy":"'.$ccy.'",
                                            "desc":"'.$decs.'",
                                            "status":"'.$status.'",
                                            "cdtDbtInd":"'.$cdtDbtInd.'",
                                            "transactionId":"'.$transactionId.'",
                                            "transactionDate":'.$miliSecond.',
                                            "transactionHash":"'.$transHash.'"
                                        }
                                    ],
                                    "totalElement":'.$totalElement.'
                                }
                            }';

                            $bakonglog->bakonglog($row['loginPhoneNumber'],'account-transaction',$JSON,'Response log data',$folderLog);
                            echo $JSON;

                        }else{
                            $JSON='{
                                "status":{
                                    "code":0,
                                    "errorCode":null,
                                    "errorMessage":null,
                                },
                                "data":null
                            }';
    
                            $bakonglog->bakonglog($row['loginPhoneNumber'],'account-transaction',$JSON,'Response log data',$folderLog);
                            echo $JSON;
                        }
                    }else{
                        $JSON='{
                            "status":{
                                "code":1,
                                "errorCode":3,
                                "errorMessage":"No account found.",
                            },
                            "data":null
                        }';

                        $bakonglog->bakonglog($row['loginPhoneNumber'],'account-transaction',$JSON,'Response log data',$folderLog);
                        echo $JSON;
                    }
                }
            }
        }
    }else{
        $JSON='{
            "status":{
                "code":1,
                "errorCode":7,
                "errorMessage":"Token is invalid."
            },
            "data":null
        }';

        $bakonglog->bakonglog('','account-transaction',json_encode($data),'Request log data',$folderLog);
        $bakonglog->bakonglog('','account-transaction',$JSON,'Response log data',$folderLog);
        echo $JSON;
    }
}
else{
    $JSON='{
        "status":{
            "code":1,
            "errorCode":7,
            "errorMessage":"Token is invalid."
        },
        "data":null
    }';
    
    $bakonglog->bakonglog('','account-transaction',json_encode($data),'Request log data',$folderLog);
    $bakonglog->bakonglog('','account-transaction',$JSON,'Response log data',$folderLog);
    echo $JSON;
}
}

function getAccountTransactions($account,$size,$phone,$folder,$url){

    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
 
    $headers = array(
       'Accept: application/json',
       'Content-Type: application/json'
    );
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
 
    $data = <<<DATA
    {
        "account": "$account",
        "size": "$size"
    }
    DATA;

    $log=new Log();
    $log->writelog($phone,'Get transaction history',$data,"Request log data:",$folder);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

    $result = curl_exec($curl);
    $log->writelog($phone,'Get transaction history',$result,"Respond log data:",$folder);

    return $result;
}

?>