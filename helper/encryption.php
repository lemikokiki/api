<?php
class Encryption{
    function encryptValue($account,$bakongwallet,$phonenumber){
        $prefix_value='BIDC_BAKONG_LINKED_ACCOUNT';
        $data='?'.$account.';'.$bakongwallet.';'.$phonenumber.';'.hash('sha1',$prefix_value).'?';

        $encryption_value = hash('sha256',$data);
        return $encryption_value;
    }

    function insert($account,$dataEncryption){
        $databaseService = new DatabaseService();
        $conn = $databaseService->getConnection();

        $query="INSERT INTO `tblencryption` (`account`,`encryptData`) VALUES ('$account','$dataEncryption')";
        $cmd=$conn->prepare($query);
        $cmd->execute();

        return $cmd;
    }

    function select($account){
        $databaseService = new DatabaseService();
        $conn = $databaseService->getConnection();

        $query="SELECT * FROM `tblencryption` WHERE `account` = '$account'";
        $cmd=$conn->prepare($query);
        $cmd->execute();

        return $cmd;
    }

    function update($account,$dataEncryption){
        $databaseService = new DatabaseService();
        $conn = $databaseService->getConnection();

        $query="UPDATE `tblencryption` SET `encryptData` = '$dataEncryption' WHERE `account` = '$account'";
        $cmd=$conn->prepare($query);
        $cmd->execute();

        return $cmd;
    }
}

?>



