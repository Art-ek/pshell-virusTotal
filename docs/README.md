<h1>Hunting Malware with Powershell and Virus Total.</h1>

In my previous articles, I've used PowerShell to demonstrate how to build a TCP port scanner,
how to find the "weak password" and how to use WMI with PowerShell for task automation. 
And I was wondering if I could build something more practical and useful from the SOC analyst or blue team if you prefer, 
point of view and eventually decided to build a simple tool to help me with hunting for malicious files.
I’m not going to talk about topics like, Reverse engineering, 
static or dynamic malware analysis or even how to analyse computer memory in searching 
for "malware Artifacts" (footprints it leaves in the system), but we will start with something much more easier.
YUP. Before you start running you should learn how to walk. Thus, when creating this “tool”
I will stick to my favourite design rule, KISS (keep it simple stupid). So, what is it all about then? 
Well, it will be about file extensions. Yes, I know this topic seems to be boring and has nothing to do with malware hunting.
But, it’s not entirely true. Hackers have been doing this since I remember and it’s the oldest method how to disguise your malicious program with fake extension. 
It’s worth to mention that Windows system hides well known extensions by default?, 
so first step would be to untick “hide extensions for known files”.

For example, your myFile.jpg may in fact be myFile.jpg.exe! If you click such file it would be executed as .exe file.
However, it still might be easy to detect, but what if attacker renames the file or 
removes extension entirely and malicious.exe becomes myPrettyPicture.jpg and later on something else will 
trigger this file to rename and execute? What then? Well, there is a magic word for that and it’s literally 
called “File Magic Number”. And this is how you could determine if a “suspicious” file is a genuine one and corresponds 
to its own extension. Think of it as a file “signature” or file ID which is hardcoded in the file. 
Detecting such “signature” in files is a very effective way of distinguishing between many file formats. 
More about file format here https://en.wikipedia.org/wiki/File_format

And this is how magic number looks like in Hexadecimal notation.
<img src=0.png</img>
