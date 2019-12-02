| Another article about Hunting malware with Powershell --> [PS for hunting malware](https://art-ek.github.io/pshell-virusTotal/) | An article about HTTP status codes –> [HTTP status codes](https://art-ek.github.io/HTTP-codes-URL-and-redirects/) |

## Hunting Malware with Powershell and Virus Total. ##

In my previous articles, I've used PowerShell to demonstrate how to build a **TCP port scanner**,
how to find the **"weak password"** and how to use WMI with PowerShell for task automation. 
And I was wondering if I could build something more practical and useful from the SOC analyst or blue team if you prefer, 
point of view and eventually decided to build a simple tool to help me with hunting for malicious files.
I’m not going to talk about topics like, Reverse engineering, 
static or dynamic malware analysis or even how to analyse computer memory in searching 
for **"malware Artifacts"** (footprints it leaves in the system), but we will start with something much more easier.
YUP. Before you start running you should learn how to walk. Thus, when creating this “tool”
I will stick to my favourite design rule, KISS (keep it simple stupid). So, what is it all about then? 
Well, it will be about file extensions. Yes, I know this topic seems to be boring and has nothing to do with malware hunting.
But, it’s not entirely true. Hackers have been doing this since I remember and it’s the oldest method how to disguise your malicious program with fake extension. 
It’s worth to mention that Windows system hides well known extensions by default?, 
so first step would be to untick **“hide extensions for known files”**.

For example, your myFile.jpg may in fact be myFile.jpg.exe! If you click such file it would be executed as .exe file.
However, it still might be easy to detect, but what if attacker renames the file or 
removes extension entirely and malicious.exe becomes myPrettyPicture.jpg and later on something else will 
trigger this file to rename and execute? What then? Well, there is a magic word for that and it’s literally 
called **“File Magic Number”**. And this is how you could determine if a “suspicious” file is a genuine one and corresponds 
to its own extension. Think of it as a file “signature” or file ID which is hardcoded in the file. 
Detecting such “signature” in files is a very effective way of distinguishing between many file formats. 
More about file format [here on wikipedia: en.wikipedia.org/wiki/File_format](https://en.wikipedia.org/wiki/File_format)

And this is how magic number looks like in **Hexadecimal notation.**

![Alt text](./0.png)

Windows calc.exe loaded into a HEX editor will show 4D 5A in hex and “MZ” - ASCII , 
which are the initials of Mark Zbikowski, one of leading developers of [MS-DOS](https://en.m.wikipedia.org/wiki/MS-DOS).

![Alt text](./1.png)

Fun fact about **HEX CODES.**

*Some Programmers use HEX codes for magic numbers as memorable words to make them very unique and sometimes even spooky :) It’s worth to mention that debuggers make use of them as well.*

Example of spooky codes

   * 0xBAADF00D – (” Bad Food”) Memory allocated by LocalAlloc() with LMEM_FIXED, but not written to.
   * 0xFEE1DEAD – (“Feel Dead”) A magic number used in the Linux reboot system call.
   * 0xDEADFA11 – (“Dead Fall”) Also used in the Apple iOS crash reports when a user quits the application

And the winner is ? ....

   * 0xB16B00B5 ("big boobs") was required by Microsoft's Hyper-V hypervisor to be used by Linux guests as   their "guest signature".[5] One proposal suggested changing it to 0x0DEFACED ("defaced").[6] Actually, it was initially changed to decimal and then replaced entirely :)

More about [HexSpeak on Wiki](https://en.wikipedia.org/wiki/Hexspeak)

So even if you change the extension of this file it still can be detected by matching the **magic number**. But obviously, even if magic number corresponds to its extension it does not guarantee that file is safe, it still might contain some malicious code. And here I thought it would be nice to verify file integrity using MD5 and SHA1 hash and upload it to **Virus Total** to determine if our file is safe or it has been tampered and contains some malicious payload. A cryptographic hash is a derived from the contents of a file, creating a unique ‘fingerprint’ that will change if the file changes. And this is how we know that file content has not been changed. And I believe it’s a great way how to establish a basic but practical **file integrity check**.

Let's create some example and play with it for a moment.

I've got an unchanged file with calculated SHA1 hash and another one after I made some changes.

![Alt text](./2.png)

They all look the same !! Did I change anything ? Yes I have added a hidden text to it !

![Alt text](./3.png)

You would not noticed any difference unless you use a Hex editor.

So they might look the same but after integrity check I can tell they are different and file content has been tampered with an additional content.

![Alt text](./4.png)
This technique is called Steganography and you can read more about it here [www.garykessler.net/library/steganography.html](https://www.garykessler.net/library/steganography.html).

OK! and now I will explain what my script does. 
I’ve created few different functions which allow me to do the following

Function **Get-FileSignature**, snippet below

```
$global:FileSignature = New-Object System.Collections.ArrayList


Get-ChildItem -Path $Path -Recurse -Exclude $Exclusion | ?{-not $_.psiscontainer -and $_.length -lt $FileSize } | %{



$Props=@{
  fullname=$_.FullName
  extension=$_.Extension
  name=$_.Name
  signature=[system.bitconverter]::ToString((Get-Content $_ -TotalCount 8 -ReadCount 1 -Encoding byte) ) -replace '-',' '
  hashes=$null
}

$Tmp= New-Object -TypeName psobject -Property $Props
$Tmp.hashes=New-Object -TypeName psobject -Property @{
  md5=Get-FileHash $_ -Algorithm MD5 | select -ExpandProperty hash
  sha256=Get-FileHash $_ -Algorithm sha1 | select -ExpandProperty hash
}

```
This function will:

1.     “Scan” your files, calculate hash md5 and sha1.

2.     Read file magic number.

3.     And saves everything in array.

Result
![Alt text](./5.png)

Or if youe use PS gridView
![Alt text](./6.png)

Next function, **Function Check-Extension**

It checks whether file has an extension, double extension or unknown extension.

This function in esence is used to match file's magic number with its corresponding extension.

Output 
![Alt text](./7.png)
![Alt text](./8.png)

You have noticed that we also have two more fields there? Their values are null for now but our next function will change it and populate the first one, called VirusTotal.

The next **Query-VirusTotal function** sends previously calculated md5 or sha1 hash to the Virus Total engine and saves returned information in our array.

Remember, to perform this step you are going to need a public API key. Simply sign in to the Virus Total portal and copy your API key to the script, and basically that’s all it takes. If you execute this function and the API key is correct you will see the following output on the screen.

![Alt text](./9.png)

Otherwise you will get one of these, so make sure your key is valid and the Virus Total address is correct.

![Alt text](./10.png)

And to display VirusTotal property use the following command.

```
PS C:\> $FilesExtension | select -ExpandProperty virustotal
```
We have much more information now. It tells us the total number of performed scans, how many scans are positives, used AV engines and even link to the Virus Total report has been included. 

And there is more!

**Function Is-Malisious?** Checks the threat-level and shows virus detection ratio !

```
snip
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

    }elseif(($positives/$max)*100 -lt 60){
        Write-Host "$($array[$x].name) probably malicious detection ratio is  -  $($ratio)% threat-level HIGH" -BackgroundColor Red
        $array[$x].AVResult="$($array[$x].name) probably malicious, detection ratio is - ($($ratio)%)"
        $array[$x].ThreatLevel="High"
 
.... snip
```

Result

![Alt text](./11.png)

And now to display only threat-level = very high we could use this combination

```
PS C:\> $FilesExtension | ?{$_.threatlevel -eq "very high"} | select fullname, threatlevel,avresult,notes | fl
```
It will display everything in very organised format

![Alt text](./12.png)

Hmm ... the **threat-level** for one of the files is very high, and I was expecting rather 4D 5A which correspondes to .exe format. In this case it would be reasonable to check Virus Total portal and analyse the scan report.

Let's extract the hyperlink and see what Virus total website.

![Alt text](./13.png)

And below command will take you directly to the scan report for that malicious file

```
PS C:\> $FilesExtension | ?{$_.name -eq "readme.jpg"} | %{ start $_.virustotal.permalink}
```

![Alt text](./14.png)

Ha! Luckily it was not malicious after all. It’s an **EICAR Anti-Virus Test File**.

The EICAR Standard Anti-Malware Test file is a special 'dummy' file which is used to test the correct operation of malware detection scanners.

So, all looks promising, the script is working fine. Virus total gives us correct reults :)




