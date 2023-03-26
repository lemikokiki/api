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

        $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',json_encode($data),'Request log data',$folderLog);

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
                    "errorMessage":"Your Session has expired"
                },
                "data":null
            }';

            $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',$JSON,'Response log data',$folderLog);
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

                $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',$JSON,'Response log data',$folderLog);
                echo $JSON;
            }else{
                if(empty($data->accNumber)){
                    $JSON='{
                        "status":{
                            "code":1,
                            "errorCode":6,
                            "errorMessage":"Missing mandatory element."             
                        },
                        "data":null
                    }';

                    $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',$JSON,'Response log data',$folderLog);
                    echo $JSON;
                }else{
                    if($row['account']==$data->accNumber){

                        // Get Account detail from T24 
                        $cif=$row['cif'];
                        $phone=$row['loginPhoneNumber'];

                        $accDetails=getAccountDetails($cif,$data->accNumber,$phone,$folderLog,$T24GetAccountDetails);

                        if($accDetails !== null){
                            $accDetails = json_decode($accDetails);
                            $status = $accDetails->result->status;

                            if($status =='00'){
                                $accStatus=$accDetails->result->data->status;
                                if($accStatus ==='ACTIVE'){
                                    $kycStautus=$accDetails->result->data->kyc;
                                    if($kycStautus ==='FULL'){
                                        
                                        $account=$accDetails->result->data->account;
                                        $accName=$accDetails->result->data->name;
                                        $ccy=$accDetails->result->data->currency;
                                        $balance=$accDetails->result->data->balance;

                                        if($accDetails->result->data->type === 'CA'){
                                            $accType='CURRENT';
                                        }else if($accDetails->result->data->type === 'SA'){
                                            $accType='SAVINGS';
                                        }

                                        if($accDetails->result->data->country=='CAMBODIA'){
                                            $country='KH';
                                        }else if($accDetails->result->data->country=='VIETNAM'){
                                            $country='VN';
                                        }
                                        $kyc='FULL';

                                        if($ccy == 'USD'){
                                            $min=0;
                                            $max=10000;
                                        }else if($ccy == 'KHR'){
                                            $min=0;
                                            $max=40000000;
                                        }

                                        $JSON='{
                                            "status":{
                                                "code":0,
                                                "errorCode":null,
                                                "errorMessage":null
                                            },
                                            "data":{
                                                "accNumber":"'.$account.'",
                                                "accName":"'.$accName.'",
                                                "accPhone":"'.$phone.'",
                                                "accType":"'.$accType.'",
                                                "accCcy":"'.$ccy.'",
                                                "accStatus":"'.$accStatus.'",
                                                "kycStatus":"'.$kyc.'",
                                                "country":"'.$country.'",
                                                "balance":'.$balance.',
                                                "limit":{
                                                    "minTrxAmount":'.$min.',
                                                    "maxTrxAmount":'.$max.'
                                                }
                                            }
                                        }';

                                        $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',$JSON,'Response log data',$folderLog);
                                        echo $JSON;
                                    }else{
                                        $JSON='{
                                            "status":{
                                                "code":1,
                                                "errorCode":14,
                                                "errorMessage":"Cannot link account due to your account not yet verified."
                                            },
                                            "data":null
                                        }';
    
                                        $bakonglog->bakonglog($row['loginPhoneNumber'],'finish-link-account',$JSON,'Response log data',$folderLog);
                                        echo $JSON;
                                    }
                                }else{
                                    $JSON='{
                                        "status":{
                                            "code":1,
                                            "errorCode":2,
                                            "errorMessage":"Account is deactivated."
                                        },
                                        "data":null
                                    }';

                                    $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',$JSON,'Response log data',$folderLog);
                                    echo $JSON;
                                }
                            }else if($status == '01'){
                                $JSON='{
                                    "status":{
                                        "code":1,
                                        "errorCode":3,
                                        "errorMessage":"No account found.",
                                    },
                                    "data":null
                                }';
    
                                $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',$JSON,'Response log data',$folderLog);
                                echo $JSON;
                            }
                            else{
                                $JSON='{
                                    "status":{
                                        "code":1,
                                        "errorCode":1,
                                        "errorMessage":"Internal server error."
                                    },
                                    "data":null
                                }';
                                
                                $bakonglog->bakonglog($phone,'account-detail',$JSON,'Response log data',$folderLog);
                                echo $JSON;
                            }
                        }else{
                            $JSON='{
                                "status":{
                                    "code":1,
                                    "errorCode":1,
                                    "errorMessage":"Internal server error."
                                },
                                "data":null
                            }';
                            
                            $bakonglog->bakonglog($phone,'account-detail',$JSON,'Response log data',$folderLog);
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

                        $bakonglog->bakonglog($row['loginPhoneNumber'],'account-detail',$JSON,'Response log data',$folderLog);
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

        $bakonglog->bakonglog('','account-detail',json_encode($data),'Request log data',$folderLog);
        $bakonglog->bakonglog('','account-detail',$JSON,'Response log data',$folderLog);
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

    $bakonglog->bakonglog('','account-detail',json_encode($data),'Request log data',$folderLog);
    $bakonglog->bakonglog('','account-detail',$JSON,'Response log data',$folderLog);
    echo $JSON;
}
}

function getAccountDetails($cif,$account,$phone,$folder,$url){

    $curl=curl_init();
    curl_setopt($curl, CURLOPT_URL, $url) ;
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
 
    $headers = array(
       'Accept: application/json',
       'Content-Type: application/json'
    );
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    $data = <<<DATA
    {
        "cif": "$cif",
        "account": "$account",
        "phone": "$phone"
    }
    DATA;

    $log=new Log();
    $log->writelog($phone,'Get account details',$data,"Request log data:",$folder);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

    $result = curl_exec($curl);
    $log->writelog($phone,'Get account details',$result,"Response log data:",$folder);

    return $result;
}


?>