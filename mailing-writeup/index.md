+++
author = true
title = "DevVortex HTB Writeup"
date = "2023-12-01"
description = "Devvortex writeup"
tags = [
    "ctf",
    "devvortex"
]
categories = [
    "themes",
    "hacking"
]
toc = true
image = "images/htb-mailing-box.png"
+++

## HTB - Mailing

Like always we start with rustscan to quickly check for open port and use nmap to run detail scan.

We have 19 open ports

Webserver - 80
SMTP - 25,465,587
POP3 - 110
SMB - 445
Windows - 135,139
Imap - 143, 993
WinRM - 5985

Other - Windows RPC

We know we are dealing with **Windows Machine** here.

![htb-mailing-rustscan.png](images/2d77fd392c001a16bf400df5363dfe50729cbd75.png)

![htb-mailing-nmap.png](images/198fc36b3e3384c2af769f3bead6d58b92300e83.png)

Let's try get into the **webserver (Port 80)** first and see what's inside. But first we have to put into our **/etc/hosts** so that our DNS can resolve.

![htb-mailing-homepageerror.png](images/397d8b490d9624d6e28fcf10bc71dac0956febc5.png)

![htb-mailing-etchosts.png](images/f88ee449706739cbdf2061e4b77e89c19de24dcc.png)

We can now enter the webpage. Now before we start poking around, let's try run our directory enumeration tools.

<figure>
<img
src="images/7782bc0520275ce3b5feebf0a7a35154f27d5458.png"
title="wikilink" alt="htb-mailing-homepage.png" />
<figcaption aria-hidden="true">htb-mailing-homepage.png</figcaption>
</figure>

I use **Dirsearch** and **GoBuster**. Let it run on the background first while we explore the website.

![htb-mailing-dirsearch.png](images/c76c14e7e61f321aad833a32de3c320b3f91cbf7.png)

![htb-mailing-gobuster.png](images/c092ca9c184940108557b4f15763ba035c895d7a.png)

Looking into the page. We know it's about **mail server** as we saw on our nmap result. We know it's using **hMailServer**.

<figure>
<img
src="images/0c72ee166429725667f0dc20babcb0ecf5e3da5d.png"
title="wikilink" alt="htb-mailing-homepage1.png" />
<figcaption aria-hidden="true">htb-mailing-homepage1.png</figcaption>
</figure>

Clicking the link bring us to the hMailServer webpage. Nothing interesting at the moment

<figure>
<img
src="images/a83d84a17264f8c46743dc57944a12290fece70e.png"
title="wikilink" alt="htb-mailing-hmailserver.png" />
<figcaption aria-hidden="true">htb-mailing-hmailserver.png</figcaption>
</figure>

On the installation part. We see "**Download Instructions**". Interestingly we can see the link. We might come back later on this.

<figure>
<img
src="images/efe0f13fd74427d87dea2ae0a70fb0b14a0bf8a8.png"
title="wikilink" alt="htb-mailing-downloadinstructions.png" />
<figcaption
aria-hidden="true">htb-mailing-downloadinstructions.png</figcaption>
</figure>

Looking into the downloaded file. It tell us how to connect to **mailing.htb** mail server.

<figure>
<img
src="images/d0c91eaa3cc8a70e8cb6d24b3def392b02eadac1.png"
title="wikilink" alt="htb-mailing-documentation.png" />
<figcaption
aria-hidden="true">htb-mailing-documentation.png</figcaption>
</figure>

Reading the file, we saw 2 user. user@mailing.htb and maya@mailing.htb. Maybe we might have to use them. Let's keep em.

<figure>
<img
src="images/c91a5471cd12f5924ae105e8bb41a49f749ba310.png"
title="wikilink" alt="htb-mailing-mayamail.png" />
<figcaption aria-hidden="true">htb-mailing-mayamail.png</figcaption>
</figure>

After gathered some information about the target. We try looking around for public exploit. We found a **hMailServer exploit** on exploit-db. We aren't sure if it's going to work, since we don't know the version of the hMAilServer.

<figure>
<img
src="images/b33a07328220a606cb6a050f64109799c4c622fa.png"
title="wikilink" alt="htb-mailing-hmailexploit.png" />
<figcaption aria-hidden="true">htb-mailing-hmailexploit.png</figcaption>
</figure>

Reading the exploit, we know that the **hMailServer** is vulnerable to LFI. And if we can find **hMailServer.INI** we might get the **Administrator Password**. So we have to find attack vector.

<figure>
<img
src="images/6ba5c6919b413e14224422c21a863914b96c878a.png"
title="wikilink" alt="htb-mailing-hmailexploit1.png" />
<figcaption
aria-hidden="true">htb-mailing-hmailexploit1.png</figcaption>
</figure>

Getting back to our dirsearch and gobuster. We didn't found much.

<figure>
<img
src="images/43632f7cee48741ece674d8de214852bbea20d2b.png"
title="wikilink" alt="htb-mailing-dirsearch1.png" />
<figcaption aria-hidden="true">htb-mailing-dirsearch1.png</figcaption>
</figure>

We check the page source for the page and found 3 more user. And also link to the download instructions.

<figure>
<img
src="images/ab3a0c2111c38bef58a9ef5e86ed51e3105d5eb0.png"
title="wikilink" alt="htb-mailing-sourcepage.png" />
<figcaption aria-hidden="true">htb-mailing-sourcepage.png</figcaption>
</figure>

I try some LFI payload on the file parameter. But then I realized we're dealing with Windows.

<figure>
<img
src="images/6142596799142e816b31804eee3f72eb95b6e45c.png"
title="wikilink" alt="htb-mailing-downloadlink.png" />
<figcaption aria-hidden="true">htb-mailing-downloadlink.png</figcaption>
</figure>

Checking the downloaded instructions again. We can try getting the **/etc/hosts** file.

<figure>
<img
src="images/388e4a17e1e5801ab8ab1668253abd144c4266a8.png"
title="wikilink" alt="htb-mailing-hostlfi.png" />
<figcaption aria-hidden="true">htb-mailing-hostlfi.png</figcaption>
</figure>

And gladly enough, we managed to get the **hosts file**. Now we have found an attack vector. Let's try getting the **hMailServer.INI**.

![htb-mailing-hostlfi1.png](images/8eeabc5934782f2edf15a20c4853f7f8ba4a7d1b.png)

![Pasted image 20240510231815.png](images/8afb70c37e163295a35a91e4e167b9d4c2d782ec.png)

After much trying and poking around the directory. We managed to download the hMailServer.INI.

<figure>
<img
src="images/413c3d55e914f84bb193838c34cfd16ef6fb7cb8.png"
title="wikilink" alt="htb-mailing-hmailserverini.png" />
<figcaption
aria-hidden="true">htb-mailing-hmailserverini.png</figcaption>
</figure>

And inside there is **Administrator username and password** Hash. Let's try cracking the password using **hashcat**.

<figure>
<img
src="images/d2d35b9bb0f7d6c1a1d32b18d654f26881b118fc.png"
title="wikilink" alt="htb-mailing-hmailserverfile.png" />
<figcaption
aria-hidden="true">htb-mailing-hmailserverfile.png</figcaption>
</figure>

We know it's MD5.

<figure>
<img
src="images/fa6dbbba844beb4f8ff9feef121fb7334435abef.png"
title="wikilink" alt="htb-mailing-hashidentifier.png" />
<figcaption
aria-hidden="true">htb-mailing-hashidentifier.png</figcaption>
</figure>

Using hashcat with rockyou wordlists.

<figure>
<img
src="images/f37cebe9fc8f3373e010f84d46d1556b4c318fdb.png"
title="wikilink" alt="htb-mailing-hashcatadmin.png" />
<figcaption aria-hidden="true">htb-mailing-hashcatadmin.png</figcaption>
</figure>

We managed to crack the password !

<figure>
<img
src="images/bb34a7d20e9800183e6e8c63b4e96aeeac5a1416.png"
title="wikilink" alt="htb-mailing-crackedadmin.png" />
<figcaption aria-hidden="true">htb-mailing-crackedadmin.png</figcaption>
</figure>

With found credential I try poking around the other Mail Server. But I just can't seem to find a way to access the email.

![htb-mailing-mailserverexploit.png](images/6b88f06ff41dcb53a8c31718ecb4e4e67ac77385.png)

![Pasted image 20240510233311.png](images/9423ea62d9b194a42f3b201b3db9b42b8feebce0.png)

We know it's using Microsoft Outlook based on the Documentation that we downloaded. So I try looking for any **exploit on Microsoft Outlook**. And we found one. And it's recent.

<figure>
<img
src="images/9e49a70da9bd05f2a5ea70392db1a05c3eedda56.png"
title="wikilink" alt="htb-mailing-outlookexploit.png" />
<figcaption
aria-hidden="true">htb-mailing-outlookexploit.png</figcaption>
</figure>

We can try using the exploit below. Basically there's a **0-Click exploit** that we can send and if the user open the email without even clicking the link. We can capture the **NTLM hashes** via **Responder**. Let's try it out.

<figure>
<img
src="images/f578620cae8a2c84e8c80eea52f01a60947e7d1a.png"
title="wikilink" alt="htb-mailing-cve2024-21413.png" />
<figcaption
aria-hidden="true">htb-mailing-cve2024-21413.png</figcaption>
</figure>

I try using other port but **port 587** works and we can send email successfully. I'm using maya@mailing.htb based on the documentation. But I just can't seem to get any respond on my responder.

<figure>
<img
src="images/ed8556f3d555cc58ca780676f19596214f4e2298.png"
title="wikilink" alt="htb-mailing-exploitoutlook.png" />
<figcaption
aria-hidden="true">htb-mailing-exploitoutlook.png</figcaption>
</figure>

After trying and trying. I try spamming the exploit multiple times in a row. And finally our Responder managed to capture the NTLMv2 hashes.

![htb-mailing-spamoutlookexploit.png](images/5a5e51aeaf661d3f2f1ac1f799b75637be5bc3f5.png)

![htb-mailing-responder.png](images/2f49bf56d731d8034540ba85bbe6c989d756f809.png)

Now we can try cracking the password using hashcat.

<figure>
<img
src="images/dcbe7bfbf048e8b07accb651431f56d7ff35a050.png"
title="wikilink" alt="htb-mailing-crackmaya.png" />
<figcaption aria-hidden="true">htb-mailing-crackmaya.png</figcaption>
</figure>

And we found maya password !
![htb-mailing-crackedmaya.png](images/c8ca4509474d576f8d1f256972894cfd2987a5cf.png)

We know from nmap that **port 5985** is open. So we can probably **WinRM** into the machine. We can make sure by using **CrackMapExec**.

<figure>
<img
src="images/a7b85e2884212e50008fcc3a49deda3d70074fc0.png"
title="wikilink" alt="htb-mailing-winrmmaya.png" />
<figcaption aria-hidden="true">htb-mailing-winrmmaya.png</figcaption>
</figure>

We can use **evil-winrm** to access the machine using the founded credential.

<figure>
<img
src="images/212eafc6a82b674cb1e5738299b11ea1e5250868.png"
title="wikilink" alt="htb-mailing-evilwinrmmaya.png" />
<figcaption
aria-hidden="true">htb-mailing-evilwinrmmaya.png</figcaption>
</figure>

Checking the **localgroup**, we know it's using spanish(?) language.

<figure>
<img
src="images/a2cfdc1317ef5fafd19545a1dca5353467f88ee0.png"
title="wikilink" alt="htb-mailing-mayagroup.png" />
<figcaption aria-hidden="true">htb-mailing-mayagroup.png</figcaption>
</figure>

Information about user Maya. We don't have much privilege here. We have to find way to escalate our privileges.
![htb-mailing-mayauser.png](images/3d67ee14062ab9d9ffe56619688762ec0e5cf98e.png)

Users that's inside this machines.

<figure>
<img
src="images/f501b47846285ef3f8a04ab8eb5c87fc554fb75b.png"
title="wikilink" alt="htb-mailing-netuser.png" />
<figcaption aria-hidden="true">htb-mailing-netuser.png</figcaption>
</figure>

Let's get the user flag first on maya Desktop.

<figure>
<img
src="images/8144bca489740ed01d1692fabdbb8a4b4c1703c2.png"
title="wikilink" alt="htb-mailing-userflag.png" />
<figcaption aria-hidden="true">htb-mailing-userflag.png</figcaption>
</figure>

I tried uploading **winPEAS** to help enumerate for us. But looks like there's **antivirus** on this machine.

<figure>
<img
src="images/6b2d9e93f7332d778bf433115aef341ed2e4f993.png"
title="wikilink" alt="htb-mailing-winpeas.png" />
<figcaption aria-hidden="true">htb-mailing-winpeas.png</figcaption>
</figure>

I also tried uploading **meterpreter** payload but same result.
![htb-mailing-meterpreter.png](images/890abf58398d2618fb185e0c709ca7316422a9e5.png)

Looks like we have to manually enumerate this machine.
![htb-mailing-usersdir.png](images/69486efa618c334480130dab899f4287ab7fc290.png)

As we expected the **localadmin** directory is required administrator privilege.
![htb-mailing-localadmindenied.png](images/4dcb71c69d16d30f393656cb2628135afca7ffac.png)

On the root directory. We found an unusual file **"Important Documents"**. But it's empty. Suspicious. But let's move on for now.

<figure>
<img
src="images/c9afd1a4f0476a147f8ce8f679f35ad569611111.png"
title="wikilink" alt="htb-mailing-rootdirectory.png" />
<figcaption
aria-hidden="true">htb-mailing-rootdirectory.png</figcaption>
</figure>

After tirelessly poking around the machine. We found a **LibreOffice version 7.4** installed in this machine.
![htb-mailing-libreoffice.png](images/19b7fbc66f9c5d36ab656e384e5536a7350983c0.png)

Quick googling and we found couple of exploit regarding this version of LibreOffice. We will go with **elweth-sec/CVE-2023-2255**.

<figure>
<img
src="images/41c2c86ff6e5bf47e37d118540ca2bba1622e875.png"
title="wikilink" alt="htb-mailing-libreofficeexploit.png" />
<figcaption
aria-hidden="true">htb-mailing-libreofficeexploit.png</figcaption>
</figure>

This exploit script exploits CVE-2023-2255 by injecting a command into an ODT file. It takes in a command and output filename via command-line arguments, then modifies the content of a sample ODT file with the provided command. After rewriting the modified content into a new ODT file, it cleans up temporary files and directories. Essentially, it automates the process of injecting potentially malicious commands into ODT files, targeting systems vulnerable to CVE-2023-2255.

<figure>
<img
src="images/faab687a593ba0f30a6eb66d7568fad16e773f27.png"
title="wikilink" alt="htb-mailing-cve-2023-2255.png" />
<figcaption
aria-hidden="true">htb-mailing-cve-2023-2255.png</figcaption>
</figure>

We try using the exploit and make it execute command to **add the user** we have access to which is maya, into **localgroup Administrator**(Administradores since it's using spanish.)

<figure>
<img
src="images/f26cb136122b54e7cc6b767cad5725481c2ba60f.png"
title="wikilink" alt="htb-mailing-explotlibreoffice.png" />
<figcaption
aria-hidden="true">htb-mailing-explotlibreoffice.png</figcaption>
</figure>

All we need to do now is download the file and put it into **"Important Documents"** directory.

<figure>
<img
src="images/df775350b6101f891bf5ab2d1f77b0b1d159d249.png"
title="wikilink" alt="htb-mailing-explotdownloaded.png" />
<figcaption
aria-hidden="true">htb-mailing-explotdownloaded.png</figcaption>
</figure>

After waiting for awhile. Maya is in Administrator group ! We can access localadmin directory now. But let's take it a step further and get actual access to localadmin.

<figure>
<img
src="images/b7685201354a62e6c333d7d54247671a74202643.png"
title="wikilink" alt="htb-mailing-mayaadmin.png" />
<figcaption aria-hidden="true">htb-mailing-mayaadmin.png</figcaption>
</figure>

We use **CrackMapExec** to ease our process on **dumping SAM Hashes**.
![htb-mailing-samdump.png](images/db9f18064f749c3e3a4f0f24889a357e6c3ccf0a.png)

Since we have the hashes. We can directly use the hashes to authenticate us into the machine. Checking the SMB it's show **Pwn3d!**. Meaning we can try use **wmiexec** or **smbexec** to get access.

<figure>
<img
src="images/8c4fe74dd261dc91e77c78752078bccaf72cb5c2.png"
title="wikilink" alt="htb-mailing-smblocaladmin.png" />
<figcaption
aria-hidden="true">htb-mailing-smblocaladmin.png</figcaption>
</figure>

I use **Impacket-Wmiexec** and voila we are now localadmin and all we have to do is grab the root flag in localadmin desktop.

![htb-mailing-wmiexeclocaladmin.png](images/e93e0544d860e0cdc513117510231c766cceaad2.png)

![htb-mailing-rootflag.png](images/7e4bf18c5b0893c7d720dab21b87cb127e033d28.png)
