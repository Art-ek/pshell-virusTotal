<#
.SYNOPSIS
    Hunting malware with powershell 
.DESCRIPTION
    Main help here
.NOTES
	It's pre beta version, very far from perfection
.EXAMPLE
The functions are: 

Get-FileSignature path $path
Get-FileSignature -path c:\download
Check-Extension
Query-VirusTotal -arrayType extensions -hash sha1
Query-VirusTotal -arrayType everything -hash md5
Is-Malicious? everything
Is-Malicious? extensions
$AVScanFound | select-string "file name or AV engine etc"
#>


$global:FullPath=""

$APIKey = 'your api key'

$Csv=import-csv "./magic.csv"

$FileSize="25MB"

$Exclusion=@("*.ps1","*.txt","*.htm*","*.log","*.gz","*.csv","*.ini","*.log")

$global:FilesExtension=@()

$global:AllFiles=@()

$global:FileSignature=@()

$global:AVScanFound = @()


function Get-FileSignature{

<#
.SYNOPSIS
Get-FileSignature function reads selected files from chosen location

Remember you have to download the magic.csv file before you run this script.
Powershell version = 4.0 is required !
 
.DESCRIPTION
This function uses the get-childitem cmdlet, known as dir or ls.
It will go through the selected folder and try to get detailed info about each file.
What info exactly?
- file magic number
- file name, extension
- md5 and sha1 hash

Also we have few variables so you can adjust your searches to your needs.
You can set the $Path variable or you can do it on the fly when calling get-signature function

$APIKey = 'here goes your API key'

$Csv=import-csv "path to your magic.csv file"

$FileSize="10MB" change it to any size you like

$Exclusion=@("*.ps1","*.txt","*.htm*","*.zip","*.gz") you can add more extensions accordingly

Result will look like the following few lines.
======================================
fullname  : F:\crack\New Text Document
extension : 
name      : New Text Document
signature : 58 35 4F 21 50 25 40 41
hashes    : @{sha1=275A021BBFB6489E54D471899F7
======================================
.EXAMPLE
Get-FileSignature -path $path
.EXAMPLE
Get-FileSignature -path c:\downloads
.EXAMPLE
Get-FileSignature  c:\downloads
#>

[CmdletBinding()]

param (
[Parameter(Mandatory=$True)]
[String]$Path


)



if (Test-Path $Path){

    Write-Host "Path tested OK"
    $global:FullPath=$Path
    pushd $Path
}
else
{
    Write-Host "Wrong path"
    break
}

$global:FileSignature = New-Object System.Collections.ArrayList

Get-ChildItem -Path $Path -Recurse -Exclude $Exclusion | ?{-not $_.psiscontainer -and $_.length -lt $FileSize  } |  %{

        $Props=@{
        fullname=$_.FullName
        extension=$_.Extension
        name=$_.Name
        signature=[system.bitconverter]::ToString((Get-Content $_ -TotalCount 8 -ReadCount 1 -AsByteStream  ) ) -replace '-',' '
        hashes=$null      
   

        }

$Tmp= New-Object -TypeName psobject -Property $Props

$Tmp.hashes=New-Object -TypeName psobject -Property @{

      md5=Get-FileHash $_ -Algorithm MD5 | select -ExpandProperty  hash
      sha1=Get-FileHash $_ -Algorithm sha1 | select -ExpandProperty  hash
   
   }

$FileSignature.Add($Tmp) | Out-Null

}

popd

$FileSignature



}






function Check-Extension {
<#
.SYNOPSIS
Checks if file has extension, double extension or unknown extension. 
.DESCRIPTION
This function is used to match file's magic number with its corresponding extension. 

.NOTES
	It's pre beta version, very far from perfection
.EXAMPLE
Check-Extension

#>


    foreach($File in $FileSignature)
    {
      

        $PropertyHolder=[ordered]@{
              Fullname=$File.fullname
              Extension=$File.Extension
              Name=$File.Name              
              Signature=$File.signature
              Hashes=$File.hashes
              VirusTotal=@()
              Notes=$null
              AVResult=@()
              ThreatLevel=""
        }  
                            
        foreach($c in $csv){


       
            if($File.extension -eq $c.Extension -and $File.signature -match $c.Magic){
       
                #write-host "Signature $($File.signature) in $($File.name) corresponds to signature $($c.magic),file type $($c.extension) which is $($c.Description.toupper()), but it still could be malicious"
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="Signature ($($File.signature)) in ($($File.name)) corresponds to signature ($($c.magic)), and file type $($c.extension) which is $($c.Description.toupper())"
                if($global:AllFiles.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:AllFiles +=$temp
                }


            }
            if($File.extension -eq $c.Extension -and $File.signature -notmatch $c.Magic){
           
                #write-host "Signature ($($File.signature)) in ($($File.name)) does not match up ($($c.magic)), and its corresponding file type $($c.extension) " -BackgroundColor red
                
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="Signature mismatch. ($($File.name)) magic number ($($File.signature)) does not match up the ($($c.magic)) and its corresponding file type ($($c.extension))  "
                if($global:FilesExtension.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:FilesExtension +=$temp
                }
                if($global:AllFiles.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:AllFiles +=$temp
                }
       
            }if(!$File.extension -and ($File.signature -match $c.Magic)){

 
                #write-host "Signature ($($File.signature)) in ($($File.name)) has no extension however signature $($c.Magic) corresponds to $($c.Extension)"   -BackgroundColor black
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="File ($($File.name)) has No extension! However this file signature ($($File.signature)) corresponds to ($($c.magic)) which is ($($c.description)) "
                
                if($global:FilesExtension.name  -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:FilesExtension +=$temp
                }
                if($global:AllFiles.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:AllFiles +=$temp
                }

            }

            }if(!$File.extension -and ($File.signature -notmatch $c.Magic)){
           

                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="File $($File.name) has No extension! And file magic number ($($File.signature)) has not been identified  "
                if($global:FilesExtension.name  -eq $File.name){                 
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                     
                    $global:FilesExtension +=$temp
                }
                if($global:AllFiles.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:AllFiles +=$temp
                }

            }   

    
    #  (catching anything else)
    
         if($File.extension -ne $c.Extension ){
       
                
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="$($File.name) has unknown extension ($($file.extension)) and cannot be recognised."
                if($global:AllFiles.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:AllFiles +=$temp
                }
                if($global:FilesExtension.name  -eq $File.name){                 
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                     
                    $global:FilesExtension +=$temp
                }


            }

}

echo "========================================================================================================"
Write-Host '
Your Scanned location was '$FullPath'
Please check $AllFiles object which contains files from scanned directory 
and $FilesExtension which contains files with no extension, double extension or signature mismatch' -BackgroundColor White -ForegroundColor Black

write-host "AllFiles  has $($global:AllFiles.Length) entries" 
write-host "FilesExtension has $($global:FilesExtension.Length) entries"

}



enum hash{
    md5
    sha1
}

enum ArrayType{
    everything
    extensions
} 

function Query-VirusTotal{
<#
.SYNOPSIS
Function to connect to Virus Total engine. 
.DESCRIPTION
This function sends a file hash, either md5 or sha1 to virus total and saves returned information in the array.

We are going to have two arrays

$AllFiles - contains all files from scanned directory 
$FilesExtension -  files with no extension or wrong signature or file with a double extension will reside here.
.NOTES
You going to need your own key, sign up and obtain your own virus total API key!
.EXAMPLE
Query-VirusTotal -arrayType extensions -hash sha1
.EXAMPLE
Query-VirusTotal everything sha1
#>

param(
    [Parameter(Mandatory=$True)]
    [Arraytype]$arrayType,
    [Parameter(Mandatory=$True)]
    [hash]$hash
)



switch($arrayType){
    "everything" {$array=$global:AllFiles;break}
    "extensions" {$array=$global:FilesExtension;break}
    default {"Wrong switch";break}
}

    foreach($a in $array)
    {

        if($a.VirusTotal.response_code -eq $null){
        
        #4 calls a minute
        sleep 15
        Write-Host "sending $($a.hashes.$hash) to Virus total"
        Write-Host "File name : $($a.name)"
        $a.VirusTotal= get-virusTotal $a.hashes.$hash
            switch($a.VirusTotal.response_code){
                0{"item you searched for was not present in VirusTotals";break}
                1{"item is present and it could be retrieved";break}
                -2{"item is still queued for analysis";break}
                default {"Response error";break}
             }
        $a.VirusTotal.verbose_msg
    }else
        {
            Write-Host "File name : $($a.name) has been checked already"
        }
}
}




function get-virusTotal{

[CmdletBinding()]
param(
[Parameter(Mandatory=$True)]
[String]$Hash
)
try{
#return $VirusTotal=$Hash |%{ Invoke-RestMethod  -Uri 'https://www.virustotal.com/vtapi/v2/file/report'  -Method 'GET' -Body @{  apikey = $APIKey; resource=$_ }}
return $VirusTotal= Invoke-RestMethod  -Uri 'https://www.virustotal.com/vtapi/v2/file/report'  -Method 'GET' -Body @{  apikey = $APIKey; resource=$Hash }
}catch{
Write-Host "$($_.Exception.Message) - please check if VT address is correct or you have valid API key" -BackgroundColor DarkRed
break
}
}



function Is-Malisious?{
<#
.SYNOPSIS
Checks the threat-level and shows virus detection ratio.
.DESCRIPTION
This function checks virus detecion ratio for each file in array (AllFiles or FileExtension)
There is another array with list of AV engines and detected viruses.
.EXAMPLE
Is-Malicious? everything
Is-Malicious? extensions
.EXAMPLE
$AVScanFound | select-string "file name or AV engine etc"
#>


param(
    [Parameter(Mandatory=$True)]
    [Arraytype]$arrayType
)


switch($arrayType){
    "everything" {$array=$global:AllFiles;break}
    "extensions" {$array=$global:FilesExtension;break}
    default {"Wrong switch";break}
}


for($x=0;$x -le $array.Length -1 ; $x++){
if($array[$x].virustotal.response_code -eq 0 -or $array[$x].virustotal -eq $null)
    {
        $array[$x].AVResult="Please scan me manually,seems that Virus Total could not find any info about $($array[$x].name) hash "
    }
    else
    {
        foreach($vir in ($array[$x].virustotal.scans | gm -MemberType NoteProperty -ErrorAction SilentlyContinue)){

            if($vir.Definition -match"detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})" ){
                if ($Matches.detected -eq 'True'){
                                  
                
                        $global:AVScanFound += "{0} - ({1}) - {2} - file {3}" -f $vir.name , $Matches.version, $Matches.result, $array[$x].name
                        
                                                                  
   
                 }


        }

}

$max=$array[$x].virustotal.total
$positives=$array[$x].virustotal.positives
if($max -eq 0 -or $max -eq $null){
Write-Host "internal error can't / by 0 or the max property is null "
} else {
$ratio=[system.math]::Round(($positives / $max)*100)
    if(($positives / $max)*100 -lt 1){
        Write-Host "$($array[$x].name) no risk, detection ratio is  $($ratio)% threat-level NONE" -BackgroundColor Green -ForegroundColor Black
        $array[$x].AVResult="$($array[$x].name) no risk, detection ratio is - ($($ratio)%)"
        $array[$x].ThreatLevel="None"

    }elseif(($positives / $max)*100 -lt 20){
        Write-Host "$($array[$x].name) probably false-positive, detection ratio is  $($ratio)% threat-level LOW" -BackgroundColor Yellow -ForegroundColor Black
        $array[$x].AVResult="$($array[$x].name) probably false-positive, detection ratio is - ($($ratio)%)"
        $array[$x].ThreatLevel="Low"
    }elseif(($positives/$max)*100 -lt 44){
        Write-Host "$($array[$x].name) could be malicious, detection ratio is  -  $($ratio)% threat-level MEDIUM" -BackgroundColor DarkYellow -ForegroundColor Black
        $array[$x].AVResult="$($array[$x].name) could be malicious, detection ratio is - ($($ratio)%)"
        $array[$x].ThreatLevel="Medium"

    }elseif(($positives/$max)*100 -lt 70){
        Write-Host "$($array[$x].name) probably malicious detection ratio is  -  $($ratio)% threat-level HIGH" -BackgroundColor Red
        $array[$x].AVResult="$($array[$x].name) probably malicious, detection ratio is - ($($ratio)%)"
        $array[$x].ThreatLevel="High"
    }else{
        Write-Host "$($array[$x].name) most likey malicious, detection  ratio is  - $($ratio)% threat-level CRITICAL" -BackgroundColor DarkRed
        $array[$x].AVResult="$($array[$x].name) most likely malicious, detection ratio is - ($($ratio)%) "
        $array[$x].ThreatLevel="Critical"
    }

}
    
}

}


}


function show-menu{
cls
$title="Powershell for Virus Total"
"=============================  $title  =========================="

"(1) - Provide path to directoty you want to scan - selected path is: $($path) "

"(2) - Scan selected location and (check magic number and calculate MD5 and sha1 files hash)"

"(3) - Check if file has no extension, double extension or signature mismatch  "
"  (3a) - Display All files from scanned folder, currently it has $($global:AllFiles.Length) entries"
"  (3b) - Display files where files extension mismatch has been detected, currently $($global:FilesExtension.Length) entries"
"(4) - Check selected files against Virus Total engine "
"(5) - Check detection ratio and other details returned from Virus Total"
"=================================================================="    

}

function display-menu{
do 
{

show-menu
$input=Read-Host "select operation q to quit"


switch($input){
    1 {
        $loc=Read-Host "Please provide location for scanning: "
        if (Test-Path $loc){
            Write-Host "Path tested OK"
        $Path=$loc
    }
    else
    {
        Write-Host "Wrong path"
        $path='no location!'
        pause
    }
    break
    }
    2 {
        $tmp=get-FileSignature $path 
        $tmp | Out-GridView 
        break
      }
    3 {
        check-extension   
        break
      }
    3a {
        if
            ($global:AllFiles.Length -gt 0){
            $global:AllFiles | select name , signature, notes, avresult, threatlevel | Out-GridView
     
       }
       break
       }
    3b {
        if
            ($global:FilesExtension.Length -gt 0){
            $global:FilesExtension | select name , signature, notes, avresult, threatlevel |Out-GridView };break}
    4 {Query-VirusTotal extensions ;break}
    5 {is-malisious? extensions ;break
      }
   
}



}until($input -eq 'q')


}





 

