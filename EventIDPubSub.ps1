#New-EventLog –LogName Security –Source "Test"
#Write-EventLog –LogName System –Source "Test" –EntryType Error –EventID 4720 –Message "This is a test message."


#Function to translate Username from SID
function GetUserName{
$objSid = New-Object System.Security.Principal.SecurityIdentifier($sid)
$user = $objSid.Translate([System.Security.Principal.NTAccount])
$user
}

function Parse-WindowsEvents(){
    param(
        [Parameter(Position=1, ValueFromPipeline)]
        #[System.Diagnostics.Eventing.Reader.EventRecord[]]$Events
        [object[]]$Events
    )
    process{
        $ArrayList = New-Object System.Collections.ArrayList
        $Events  | %{
            $EventObj = $_
            $EventObjFullName = $_.GetType().FullName
            if($EventObjFullName -like "System.Diagnostics.EventLogEntry"){   
                $EventObj = Get-WinEvent -LogName security -FilterXPath "*[System[EventRecordID=$($_.get_Index())]]"
            }elseif($EventObjFullName -like "System.Diagnostics.Eventing.Reader.EventLogRecord"){

            }else{
                throw "Not An Event System.Diagnostics.Eventing.Reader.EventLogRecord or System.Diagnostics.EventLogEntry"
            }
            $PsObject =  New-Object psobject
            $EventObj.psobject.properties | %{
                $PsObject | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
            }
            $XML = [xml]$EventObj.toXml()
            $PsObject2 = New-Object psobject
            $XML.Event.EventData.Data | %{
                $PsObject2 | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_."#text"
            }
            $PsObject | Add-Member -MemberType NoteProperty -Name ParsedMessage -Value $PsObject2
            $ArrayList.add($PsObject) | out-null
        }
        return $ArrayList
    }
}

#$EventId = 4720,4722,4724,4725,4726,4728,4741,4743,5136
#$A = Get-WinEvent -FilterHashtable @{LogName='Security'; id=4725} |
#Select TimeCreated, @{N='UserName';E={GetUserName $_.UserId}},@{N='ComputerName'; E={$_.MachineName}}, @{N='Event_ID'; E={$_.ID}},
#@{N='Message'; E={$_.Message}}, @{N='ProviderName'; E={$_.ProviderName}} 

$id= Get-WinEvent -FilterHashtable @{LogName='Security';id=4725} | Select-Object -First 1
if($id.Id -eq 4725)
{
$id.Event_Id
$RealUser = ($id | Parse-WindowsEvents | select -ExpandProperty ParsedMessage).TargetUserName
$User = '["testtest"]'
$NewUser = $User.Replace('testtest', $RealUser)
$Test = $RealUser
$Test = $Test.ToCharArray()
if ($Test[-1] -eq '$') {Write-Host "Computer not User"}
else{
$MSG = New-GcpsMessage -Data $NewUser
write-host($User.Data) 
Publish-GcpsMessage -Message @($MSG) -Topic "member" -Project "cloud-custodian-328316" 
}
$Message = $A.Message
$EventID = $A.Id
$MachineName = $A.MachineName
$Source = $A.ProviderName


#$EmailFrom = "no-reply@meditech.com"
#$EmailTo = "admonitor-testing-group@meditech.com"
#$Subject = "Alert From $MachineName"
#$Body = "EventID: $EventID`nSource: $Source`nMachineName: $MachineName `nMessage: $Message"
#$SMTPServer = "http://atmailrelay.meditech.com"


#$SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 25)
#$SMTPClient.EnableSsl = $true
#$password = 'fctpeawmgagvhvxc'
#[SecureString]$securepassword = $password | ConvertTo-SecureString -AsPlainText -Force
#$SMTPClient.Credentials = New-Object System.Net.NetworkCredential("admonitor-testing-group@meditech.com", $securepassword)
#$SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)
}
