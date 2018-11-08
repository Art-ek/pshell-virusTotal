
#$path="you folder path "

$APIKey = 'virusTotal apikey'

$Csv=import-csv "magic.csv"

$Exclusion=@("*.ps1","*.txt","*.htm*")

$global:FilesExtension=@()

$global:AllFiles=@()

$global:FileSignature=@()

$global:AVScanFound = @()


function get-FileSignature{

[CmdletBinding()]

param (
[Parameter(Mandatory=$True)]
[String]$Path


)



if (Test-Path $Path){

    Write-Host "Path tested OK"
    cd $Path
}
else
{
    Write-Host "Wrong path"
    break
}

$global:FileSignature = New-Object System.Collections.ArrayList

Get-ChildItem -Exclude $Exclusion | ?{-not $_.psiscontainer -and $_.length -lt 5MB  } |  %{

    $Props=[ordered]@{
   
        extension=$_.Extension
        name=$_.Name
        signature=[system.bitconverter]::tostring((Get-Content $_ -TotalCount 8 -ReadCount 1 -Encoding byte) ) -replace '-',' '
        hashes=$null
        
   

    }

$Tmp= New-Object -TypeName psobject -Property $Props

$FileSignature.Add($Tmp) | Out-Null


$Tmp.hashes=New-Object -TypeName psobject -Property @{

      md5=Get-FileHash $_ -Algorithm MD5 | select -ExpandProperty  hash
      sha256=Get-FileHash $_ -Algorithm sha256 | select -ExpandProperty  hash
   
   }

}



}


function check-allFiles{



foreach($File in $FileSignature){
   
                
$PropertyHolder=[ordered]@{
        Extension=$File.Extension
        Name=$File.Name
        Signature=$File.signature
        
        Hashes=$File.hashes
        VirusTotal=@()
        Notes=$null
        AVResult=@()
        

        }

                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="This file  ,$($File.name) could be malicious, MD5 will be checked with Virus Total engine  "
                
                if($global:AllFiles.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:AllFiles +=$temp
                }


}
}


function check-extension {



    foreach($File in $FileSignature){
   
        foreach($c in $csv){

$PropertyHolder=[ordered]@{
        Extension=$File.Extension
        Name=$File.Name
        Signature=$File.signature
        
        Hashes=$File.hashes
        VirusTotal=@()
        Notes=$null
        AVResult=@()
        }         

       
            if($File.extension -eq $c.Extension -and $File.signature -match $c.Magic){
       
                write-host "Signature $($File.signature) in $($File.name) does match up $($c.magic), the file type $($c.extension) which is $($c.Description.toupper()),but it still might be MALICIOUS!!"
                
            }
            elseif($File.extension -eq $c.Extension -and $File.signature -notmatch $c.Magic){
           
                write-host "Signature $($File.signature) in $($File.name) does not match up $($c.magic), the file type $($c.extension) " -BackgroundColor red
                
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="Signature mismatch ,$($File.name) could be malicious, MD5 will be checked with Virus Total engine  "
                #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                if($global:filesExtension.name -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:filesExtension +=$temp
                }
       
            }elseif(!$File.extension -and $File.signature -match $c.Magic){
 
                write-host "Signature $($File.signature) in $($File.name) has no extension however signature $($c.Magic) does math up the $($c.Extension)"   -BackgroundColor black
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="File has No extension! ,$($File.name) could be malicious MD5 will be checked with  Virus Total engine  "
                #$temp._Extensions+=$c.Extension
                if($global:filesExtension.name  -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:filesExtension +=$temp
                }

            }elseif(!$File.extension -and $File.signature -notmatch $c.Magic)
            {
                $temp  = new-object -TypeName psobject -Property $PropertyHolder
                $temp.notes="File has No extension! ,$($File.name) could be malicious MD5 will be checked with  Virus Total engine  "
                #$temp._Extensions+=$c.Extension
                if($global:filesExtension.name  -eq $File.name){
                    continue
                }else
                {
                    #$temp.VirusTotal= get-virusTotal $File.hashes.md5
                    $global:filesExtension +=$temp
                }
            }
   
  

   }

}
}

function query-virusTotal{
param(
[Parameter(Mandatory=$True)]
[array]$array
)
foreach($a in $array)
{
#4 calls a minute
sleep 17
$a.VirusTotal= get-virusTotal $a.hashes.md5
$a.name
$a.VirusTotal.response_code
$a.VirusTotal.verbose_msg
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
param(
[Parameter(Mandatory=$True)]
[array]$array
)

for($x=0;$x -le $array.Length -1 ; $x++){
if($array[$x].virustotal.response_code -eq 0)
    {
    $array[$x].AVResult="Please scan me manually,seems that Virus Total could not find any info abot MD5 $($array[$x].name) hash "}
    else
    {
    foreach($vir in ($array[$x].virustotal.scans | gm -MemberType NoteProperty -ErrorAction SilentlyContinue)){

        if($vir.Definition -match"detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})" ){
            if ($Matches.detected -eq 'True'){
                
                    $global:AVScanFound += "{0} - ({1}) - {2} - file {3}" -f $vir.name , $Matches.version, $Matches.result, $array[$x].name

                    $array[$x].AVResult+=@(
                    $vir.name;
                    $array[$x].name;
                    $Matches.result
                    )                            
   
             }else{
                    $array[$x].AVResult="Wahey $($array[$x].name) is not malicious  "
             }


        }

}
}
    
}
$global:AVScanFound
}


#get-signature -path

#get-extension

#check-all
