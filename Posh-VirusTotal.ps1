

$global:FullPath=''

$APIKey = 'c3f307a9a433cca488e357db85393f4292114d1bc6ba39de4703fe4814174226'

$Csv=import-csv "C:\Users\arcys\Documents\powershell\magic.csv"

$FileSize="10MB"

$Exclusion=@("*.ps1","*.txt","*.htm*","*.zip","*.gz")

$global:FilesExtension=@()

$global:AllFiles=@()

$global:FileSignature=@()

$global:AVScanFound = @()


function get-FileSignature{

<#
.SYNOPSIS
This is my abc function
.DESCRIPTION
This function is used to demonstrate writing doc
comments for a function.
.NOTES
	Its pre beta version, do not expect miracles.
.EXAMPLE
fff
.EXAMPLE
iiioi
#>

[CmdletBinding()]

param (
[Parameter(Mandatory=$True)]
[String]$Path


)



if (Test-Path $Path){

    Write-Host "Path tested OK"
    $global:FullPath=$Path
    cd $Path
}
else
{
    Write-Host "Wrong path"
    break
}

$global:FileSignature = New-Object System.Collections.ArrayList

Get-ChildItem -Path $Path -Recurse -Exclude $Exclusion | ?{-not $_.psiscontainer -and $_.length -lt $FileSize  } |  %{

        $Props=[ordered]@{
        fullname=$_.FullName
        extension=$_.Extension
        name=$_.Name
        signature=[system.bitconverter]::ToString((Get-Content $_ -TotalCount 8 -ReadCount 1 -Encoding byte) ) -replace '-',' '
        hashes=$null      
   

        }

$Tmp= New-Object -TypeName psobject -Property $Props

$Tmp.hashes=New-Object -TypeName psobject -Property @{

      md5=Get-FileHash $_ -Algorithm MD5 | select -ExpandProperty  hash
      sha256=Get-FileHash $_ -Algorithm sha256 | select -ExpandProperty  hash
   
   }

$FileSignature.Add($Tmp) | Out-Null

}

$FileSignature



}






function check-extension {
<#
.SYNOPSIS
This is my abc function
.DESCRIPTION
This function is used to demonstrate writing doc
comments for a function.
.NOTES
	Its pre beta version, do not expect miracles.
.EXAMPLE
fff
.EXAMPLE
iiioi
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
        }  
                            
        foreach($c in $csv){

       
            if($File.extension -eq $c.Extension -and $File.signature -match $c.Magic){
       
                #write-host "Signature $($File.signature) in $($File.name) corresponds to signature $($c.magic),file type $($c.extension) which is $($c.Description.toupper()),but it still might be MALICIOUS!!"
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="Signature $($File.signature) in $($File.name) corresponds to signature $($c.magic), file type $($c.extension) which is $($c.Description.toupper()),but it still might be MALICIOUS!!"
                if($global:AllFiles.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:AllFiles +=$temp
                }


            }
            elseif($File.extension -eq $c.Extension -and $File.signature -notmatch $c.Magic){
           
                #write-host "Signature $($File.signature) in $($File.name) does not match up $($c.magic), and corresponding file type $($c.extension) " -BackgroundColor red
                
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="Signature mismatch ,$($File.name) could be malicious - it does not match up the $($c.magic) signature which corresponds to ($($c.extension)) file type, the file hash will be checked with Virus Total engine  "
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
       
            }elseif(!$File.extension -and $File.signature -match $c.Magic){
 
                #write-host "Signature $($File.signature) in $($File.name) has no extension however signature $($c.Magic) corresponds to $($c.Extension)"   -BackgroundColor black
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="File $($File.name) has No extension! file Signature $($File.signature) corresponds to $($c.magic), It could be malicious, this file hash will be checked with Virus Total engine  "
                
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

            }elseif(!$File.extension -and $File.signature -notmatch $c.Magic)
            {
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="File $($File.name) has No extension! it could be malicious the file hash will be checked with Virus Total engine  "
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
    sha256
}

enum ArrayType{
    everything
    extensions
} 

function query-virusTotal{
<#
.SYNOPSIS
This is my abc function
.DESCRIPTION
This function is used to demonstrate writing doc
comments for a function.
.NOTES
	Its pre beta version, do not expect miracles.
.EXAMPLE
fff
.EXAMPLE
iiioi
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
    }else{
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

#return $VirusTotal=$Hash |%{ Invoke-RestMethod  -Uri 'https://www.virustotal.com/vtapi/v2/file/report'  -Method 'GET' -Body @{  apikey = $APIKey; resource=$_ }}
return $VirusTotal= Invoke-RestMethod  -Uri 'https://www.virustotal.com/vtapi/v2/file/report'  -Method 'GET' -Body @{  apikey = $APIKey; resource=$Hash }

}

function is-malisious?{
<#
.SYNOPSIS
This is my abc function
.DESCRIPTION
This function is used to demonstrate writing doc
comments for a function.
.NOTES
	Its pre beta version, do not expect miracles.
.EXAMPLE
fff
.EXAMPLE
iiioi
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
    if(($positives / $max)*100 -lt 20){
        Write-Host "$($array[$x].name) probably false-positive, detection ratio is  $($ratio)%" -BackgroundColor Green
        $array[$x].AVResult="$($array[$x].name) posible false-positive, detection ratio is  $($ratio)%"
    }elseif(($positives/$max)*100 -lt 44){
        Write-Host "$($array[$x].name) could be malicious, detection ratio is  -  $($ratio)%" -BackgroundColor Yellow -ForegroundColor Black
        $array[$x].AVResult="$($array[$x].name) could be malicious, detection ratio is  $($ratio)%"

    }elseif(($positives/$max)*100 -lt 60){
        Write-Host "$($array[$x].name) possibly malicious detection ratio is  -  $($ratio)%" -BackgroundColor Red
        $array[$x].AVResult="$($array[$x].name) probably malicious, detection ratio is  $($ratio)%"
    }else{
        Write-Host "$($array[$x].name) most likey malicious, detection  ratio is  - $($ratio)%" -BackgroundColor DarkRed
        $array[$x].AVResult="$($array[$x].name) most likely malicious, detection ratio is - $($ratio)% "
    }

}
    
}

}


}

<#
function show-menu{
cls
$title="Powershell for Virus Total"
"=============================  $title  =========================="

"(1) - Provide path to directoty you want to scan - selected path is: $($path) "

"(2) - Scan selected location and (check magic number and calculate MD5 and SHA256 files hash)"

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
    1 {$loc=Read-Host "Please provide location for scanning: "
    if (Test-Path $loc){

        Write-Host "Path tested OK"
        $Path=$loc
    }
    else
    {
        Write-Host "Wrong path"
        $path='no location!'
        pause
    };break}
    2
    {get-FileSignature $path ;break}
    3
    {check-extension
       pause;break}
    3a
    {if($global:global:AllFiles.Length -gt 0){
    $global:global:AllFiles
    pause
    };break}
    3b
    {if($global:FilesExtension.Length -gt 0){
    $global:FilesExtension
    pause
    };break}
    4{;break}
    5{is-malisious?;break}
    6{}
}



}until($input -eq 'q')


}

#>



 

#get-signature -path

#get-extension

#check-all
