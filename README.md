# Network Security Strategies and Applications
## 1. Network Security Practices and Tools
## 1.1 Introduction
Network security measures prioritize the protection of data during its transmission. The concept of interconnected networks arises from the fact that all workplaces, including businesses, public institutions, and universities, are connected through networks [1]. Network security practices and tools are crucial in today's digital world for organizations to protect their information systems and defend against cyber threats. Security applications such as firewalls and antivirus software monitor network traffic, detect potential threats, and prevent them. Additionally, various security tools assist organizations in continuously optimizing their security measures through vulnerability scans, security tests, and attack simulations. These applications and tools play a critical role in strengthening cybersecurity strategies, providing effective defense against cyber threats for organizations. To ensure data security, computer users need antivirus programs to protect against potential attacks in both computer and web environments. The presence of fake antivirus programs and viruses on the internet poses a significant threat [2].

Firewalls and antivirus software are fundamental security applications.

### 1.1.1 Firewall
The role of firewalls is to establish an active security system against potential attacks and threat elements from the Internet. They achieve this by controlling whether permitted services or network systems can access or be accessed by the resources or systems to be offered or used. When needed, they convert private IP address systems used in internal network environments into public IP address systems existing on the Internet and thus hide the IP addresses used within the internal networks. This allows two-way application of restrictions and filtering processes based on services, protocols, IP addresses, or users for requests coming from outside or going from inside to outside [3].

#### 1.1.1.1 Packet Filtering Firewalls
Packet filtering is the simplest packet monitoring method. Packet-filtering firewalls precisely filter packets as they pass through based on predefined rules or filters in the packet header information. The decision to accept or reject is based on the results of this comparison. Each packet is examined independently of other packets. Packet-filtering firewalls are generally referred to as filtering at the network or transport layer [3]. These firewalls evaluate data packets on the network based on fundamental features such as source and destination IP addresses, port numbers, and protocols, determining allowed or blocked traffic. They include various methods such as Access Control Lists (ACL)-based filtering, port-based filtering, and IP protocol-based filtering.

#### 1.1.1.2  Circuit-Level Firewalls
These firewalls only allow external information flow when a request comes from inside computers. Outgoing requests are recorded, and only the response corresponding to the request is allowed. The significant advantage of this type of firewall is that outsiders see the entire network only as the address of the firewall. This way, the rest of the network is protected. For example, if a computer A in a network behind the firewall wants to view a web page from an external computer B, when A sends a request to view the web page, the firewall captures and records this request. Computer B receives the request and starts sending back the web page. When the packets reach the firewall, the incoming packets are compared with A's request. Ultimately, the packet is either allowed or discarded [3].

The advantage of circuit-level firewalls is that they do not allow entry from outside to inside until the firewall is open. All ports are closed until the firewall opens. The main disadvantage is that it allows any data request from inside unless combined with other filtering methods [4].

#### 1.1.1.3 Application-Level Firewalls
Also known as Proxy Servers, these firewalls, similar to circuit-level firewalls, act as a single pass for entering and exiting the network. The critical difference is in how they handle information. While circuit-level firewalls look at the address and port information, application-level firewalls inspect packets more detailed, examining content. Firewalls using this method run proxy server applications before allowing packets containing common data types to pass through. There are two significant advantages to this approach. First, it does not allow direct connection between external resources and computers behind the security firewall. Second, it enables filtering by examining the content, considering the nature of the data [3].

Application-level firewalls are security devices that analyze and evaluate network traffic at the application layer, layer 7. Essentially, they filter traffic by examining not only source and destination IP addresses and port numbers but also the protocols and contents of communicating applications. These firewalls detect malicious content based on web application, protocol compliance, and content-based rule sets. By performing application-level security controls such as user authentication, authorization, and content filtering, they help organizations implement a more effective security policy. Application-level firewalls provide comprehensive security, especially in modern and complex network environments.

#### 1.1.1.4 Positive Effects of Firewalls
When properly implemented, firewalls can control incoming and outgoing traffic on the network. They can prevent unauthorized access from external users or networks to internal networks and services. Simultaneously, they can prevent internal users from accessing external networks or services for which they lack permissions. Firewalls can also provide opportunities for inspection and logging. Configuring firewalls in this way allows collected information to be analyzed later. Firewalls can generate various statistics from the collected data, which can be highly beneficial for making security decisions related to network access and usage [3].

Firewalls can be used to enforce access controls for departments or other private networks aiming to control access to services. Firewalls can offer logging and reporting capabilities, providing insights into network access and usage for future analysis. They play a crucial role in protecting computer networks and providing defense against cyber threats. By establishing access control, acting as the first line of defense against cyber attacks, ensuring data security, providing application-level control, and content filtering capabilities, firewalls stand out as a fundamental security measure in implementing cybersecurity policies.

#### 1.1.1.5 Negative Effects of Firewalls
Despite the many benefits of firewall solutions, they also have negative impacts. Firewalls can cause traffic congestion in some networks where all traffic must pass through the firewall. In situations where all network traffic is forced to go through the firewall, there is a high likelihood of congestion [3].

Performance loss, accessibility issues, and high costs are factors that fall among the negative effects of firewalls. Additionally, false positives/negatives and user complexity can also affect the effectiveness of firewalls. Therefore, firewalls must be configured correctly, regularly updated, and attention should be paid to factors such as user experience and business continuity.

### 1.1.2 Antivirus Software
The term "antivirus" refers to security software that provides protection against viruses and, more broadly, detects, prevents, and removes all types of malicious software [6]. Antivirus programs are designed to protect computers from harmful programs. While antivirus programs are generally tasked with finding and removing malicious programs, they may have additional functions based on user preferences [5].

The development of antivirus software is categorized into four generations:

• *First generation:* Simple scanners: First-generation scanners require virus signatures to identify the virus. Scanners that rely on specific signatures have limited functionality in detecting known viruses.

• *Second generation:* Intuitive/exploratory scanners: Second-generation software does not rely on a specific signature. These scanners use more intuitive/exploratory rules and primarily scan for the possibility of being a virus. They analyze the tendency of viruses to encrypt and find the encryption key accordingly.

• *Third generation:* Active traps, tricks: Third-generation software detects viruses is by setting traps and tricks [5]. The software monitors the computer and determines whether any application or program increases its privileges. If an application suddenly attempts to gain administrator privileges, it may be identified as a virus.

• *Forth generation:* Full-featured protection: Antivirus software belonging to this generation are packages containing different antivirus techniques. These software include scanning and active trap elements [3].

More complex antivirus approaches and products continue to evolve. It is one of the general analysis and digital immune system development techniques.

#### 1.1.2.1 General analysis
Generic analysis technology uses fast scanning, allowing even the most complex polymorphic viruses to be easily found. In order for a file containing a polymorphic virus to be executed, the virus must analyze itself. To find such a structure, current files are passed through a general analysis scanner. This browser contains the following elements [3].

- *CPU emulator:* The emulator contains software versions of the hardware processors and all registers, so that the basic procedure is not affected by the programs interpreted in the emulator.

- *Virus signature scanner:* Model that searches for known virus signatures and examines the target code.

- *Emulator control module:* Controls the execution of the target code.

#### 1.1.2.2 digital immune system
The reason for the development of this system is the increasing threat of Internet-based virus spread. Digital immune system is a concept that includes a series of measures aimed at protecting computer systems against cyber threats. These measures include elements such as antivirus and antimalware software, firewalls, security policies, training, vulnerability scans, security tests, software updates and two-factor authentication. By combining these components, computer systems are made more resilient and secure against cyber threats. The digital immune system offers an effective defense against cyber attacks by ensuring that computer systems remain up-to-date and protected in environments where technology is rapidly evolving.

The success of the digital immune system depends on the ability of the virus analyzer to detect new virus damage. It should be possible to continuously update digital immunity software to avoid threats by constantly analyzing and controlling stray viruses [7].

### 1.1.3 Cryptography and encryption tools
Cryptography is a technique of ensuring security by encoding messages in an unreadable way by converting plain text into ciphertext using various encryption algorithms. Cryptography in computer science is the use of cryptography techniques and encryption algorithms to transform messages in ways that are difficult to decipher. It does this through a set of rule-based calculations called algorithms. These deterministic algorithms use cryptographic key generation and digital signing and verification methods to ensure data, web, credit card and email confidentiality [8].

The strength of the encryption method is not related to the obscurity of the algorithm, but to the length of the key used. While encrypted data can be easily opened by using a key, if the key is not known, obtaining the data is impossible due to the intensity of mathematical operations [9].

*Plaintext:* Original, plain text.

*Ciphertext:* Encrypted text.

*Cipher:* Algorithm that converts plaintext into encrypted text. Encryption algorithm.

*Encipher (encrypt):* Converting plain text to encrypted text.

*Decipher (decrypt):* Recovering plaintext from ciphertext.

*Cryptography:* Encryption methods and principles.

*Cryptanalysis:* Code breaking. Methods and principles of decryption without using a password or key.

*Cryptology:* It refers to all the methods and principles of cryptography and cryptology [8].

There are two types of encryption algorithms: symmetric key and asymmetric key encryption [3].

#### 1.1.3.1 Symmetric key encryption
It is also called secret key encryption or single key encryption. It is a more traditional method where a single key is used for both encryption and decryption purposes. Symmetric key encryption does not cause any delay in encrypting and decrypting data. In symmetric key encryption, since data encrypted with one key cannot be opened with another key, a degree of authentication is provided if the key is kept secret [3].

#### 1.1.3.2 Asymmetric key encryption
Asymmetric encryption, also known as public key encryption, uses public and private key pairs to encrypt and decrypt data. It is the most complex technique among cryptography techniques. The public key is used for encryption and the private key is used for decryption. A key in the pair can be shared with anyone; this is called a public key. The other key in the pair is kept secret; this is called a private key. Encryption algorithms can use either key to encrypt a message. The inverse of the key used to encrypt the message is used for decryption [8].

#### 1.1.3.3 Steganography technique
Unlike encryption, which attempts to hide content so that it cannot be understood, the goal of steganography is to hide the truth present in the object or content in question by placing something else to hide it. This is a type of hiding method without using encryption.

#### 1.1.3.4 Hashing Technique
Hashing is an encryption technique that converts data in any form into a unique string. Regardless of size or type, any data can be hashed using hash encryption algorithms. It takes random length data and converts it to a fixed hash.

Hashing is different from other encryption methods because encryption algorithms encrypt data in a way that cannot be decrypted. MD5, SHA1, SHA 256 are commonly used hash algorithms. One of the areas of use of this technique is membership systems. The readable password of the user who is a member of the system is irreversibly encrypted with the hash algorithm and recorded in the database. Every time the user logs into the system, his/her readable password is re-encrypted by the hash algorithm to ensure authentication [8].

## 2. Security Audits and Tests
## 2.1 Introduction
Security audits and tests are security practices that are of critical importance for organizations today in the face of rapidly developing technology and increasing cyber threats. In an environment where information systems and network infrastructures are constantly under threat, security audits allow organizations to effectively evaluate security policies and measures, identify vulnerabilities and remediate these vulnerabilities. It is also an important process to increase resilience against cyber attacks and continuously improve security measures. Security audits and tests stand out as a security strategy that enables organizations to protect their information assets against cyber threats.

Network security audits play an important role in assessing the security of an organization's network infrastructure and identifying potential risks.

1. *Risk Assessment:* Network security audits evaluate the security posture of organizations by identifying potential risks. This helps predict potential attacks.

2. *Achieving Compliance:* Many industries have compliance requirements with laws and regulations. Network security audits are important to meet these compliance requirements and ensure the organization remains in compliance with the law.

3. *Data Confidentiality and Integrity:* Network security audits evaluate the measures taken to protect the confidentiality and integrity of data. This ensures that sensitive information is protected from unauthorized access.

4. *Advanced Threat Detection:* Audits can help organizations detect advanced threats that exist on their networks. This provides early warning by identifying unusual or potentially harmful activity.

5. *Organizational Reputation:* A secure network infrastructure increases customer and partner trust. Network security audits demonstrate to customers and stakeholders the organization's commitment to security measures.

1. *Vulnerability Scanning:* Network security audits usually start with vulnerability scanning. This means using automated tools to identify potential vulnerabilities found in the network.

2. *Penetration Tests:* After weaknesses are identified, penetration tests are performed. These tests simulate how an attacker can infiltrate the system and extend privileges.

3. *Review of Security Policies:* Network security audits review the security policies of the organization and check whether these policies are implemented.

4. *Network Traffic Inspection:* Real-time network traffic analysis is used to identify unusual activities on the network and detect potential threats.

5. *Physical Security Controls:* Network security controls also include physical security controls of server rooms and network equipment. It is important to ensure physical access control.

### 2.1.1 Penetration Test
Penetration testing is a controlled security assessment performed to identify vulnerabilities of a computer system, network or application and to test its resistance to these vulnerabilities. This test is used to strengthen the information security of organizations, to be ready against potential threats and to evaluate security measures. The phases of penetration testing include information gathering, vulnerability analysis, attack phase, authorization acquisition, analysis and reporting. These tests help organizations improve their security strategies and become more resilient against cyber threats. The results obtained are presented in the form of a report containing the criticality of the identified security vulnerabilities and suggestions for correction.

It basically consists of finding violations at a certain security level and then mitigating these violations, inspecting existing security mechanisms to ensure that the necessary steps are taken, and trying to bypass these mechanisms.
The number, knowledge and skills, time and motivation of people attacking data networks and systems are always greater than the time, knowledge and motivation of security experts. If information security is basically divided into two, one is protective security, also called defensive security, and the other is proactive security. Penetration testing studies are the result of a proactive security approach.

Performing a penetration test consists of several stages. Thanks to this test, security vulnerabilities are checked and reported from the perspective of an external attacker. The security measures within the systems are often not sufficient and the measures cannot remain up to date. In addition, the increase in the number of malicious people and the fact that their knowledge level is generally ahead of many company employees reveals the importance of pentesting. Pentest ensures that up-to-date measures are taken against internal and external threats for a company's information systems and that vulnerabilities are eliminated.

The purpose of this process is to reveal vulnerabilities in the specified target systems. For this purpose, banners on server services can be used in the first stage. In addition, these systems are scanned separately with more than one vulnerability scanning tool to try to reduce the false positive rate that may occur [1].

Below are the basic tools used for the vulnerability scanning process.

#### 2.1.1.1 NESSUS
It is one of the first open code vulnerability scanners in the security community. The licensing model has changed with the 3.x version. It can be used free of charge for non-commercial purposes. It is one of the best vulnerability scanners on the market. It has its own vulnerability definition language (NASL) [1].

#### 2.1.1.2 NEXPOSE
Nexpose for Rapid7 is a security scanner that aims to support the entire vulnerability management lifecycle. It includes discovery, detection, verification, risk classification, impact analysis, reporting and mitigation sections (Soğukpınar (2010)).

#### 2.1.1.3 NETSPARKER
Netsparker is a web application security scanner that includes detection and exploits. After a successful exploitation, it reports the confirmed vulnerabilities, otherwise it tests what it finds. This tool is explained in detail on the Netsparker website [1].

Below are the basic tools used for the infiltration process.

#### 2.1.1.4 METASPLOIT
Open source exploit development and execution tool. It contains around 600~ working exploits. Operations such as information collection and network discovery can be performed with Aux modules. It can be run from web, GUI and console. It has advanced AV, IPS bypass features. It is one of the tools that a security guard must use. It was acquired by Rapid7 company [1].

#### 2.1.1.5 CORE IMPACT
Although expensive, it is widely considered to be the most powerful machining tool. Thanks to its regularly updated database, it can easily exploit other machines through the tunnel it establishes by making professional exploits (Soğukpınar (2010)).

Below are the basic tools used for the password cracking process.

#### 2.1.1.6 JOHN THE RIPPER
John the Ripper is a password cracking software. It is generally used to crack encrypted passwords and detect weak passwords. John the Ripper is a tool that supports various encryption methods (hashes) and applies different attack techniques to break them. There are many types of attacks such as brute force attack, dictionary attack, hybrid attack and many more.

- John the Ripper supports commonly used encryption methods such as DES, MD5, SHA-1, SHA-256, SHA-3. In this way, it can crack various password hashes.
- Dictionary attacks are based on trying passwords using words and combinations in a specific dictionary file. John the Ripper can perform such attacks.
- Provides the ability to try passwords with brute force attacks. However, since such attacks are generally not effective, more sophisticated attack techniques are often preferred.
- A more effective attack strategy is followed by combining Hybrid Attacks, brute force and dictionary attacks [1].

#### 2.1.1.7 HYDRA
In the field of computer security, Hydra is a password cracking and attack tool. This tool attempts to challenge encryption systems by targeting various network protocols. In particular, it can perform brute-force attacks and thus tries to gain unauthorized access to encrypted systems. Hydra can be used on Linux-based systems and many other operating systems [1].


## 3. Conclusion and Evaluation
Network security is of great importance in today's digital environment. Basic tools such as firewalls, antivirus software and cryptography play a critical role in protecting and securing organizations' information systems against cyber threats. Firewalls keep network traffic under control by providing effective protection against attacks over the internet. While antivirus software protects computer systems from malicious software, cryptography and encryption tools ensure secure communication by ensuring the confidentiality and integrity of data. These measures aim to make organizations more resilient against cyber threats and ensure data security.

Security audits and testing play a critical role in evaluating and improving organizations' countermeasures against cyber threats. Network security audits focus on important functions such as risk assessment, compliance, data privacy, threat detection and reputation management. Penetration tests, on the other hand, are carried out as controlled security assessments to strengthen information security, be ready against threats and evaluate security measures. Tools used in these processes include powerful security tools such as Nessus, Nexpose, Netsparker, Metasploit, Core Impact, John the Ripper and Hydra. These audits and tests make organizations more resilient to cyber threats and help them continuously improve their security strategies.

 

## 4. Referances
[1] Istanbul Commerce University Journal of Science, İstanbul Ticaret Üniversitesi Fen Bilimleri Dergisi, 16(31), Bahar 2017
http://dergipark.gov.tr/ticaretfbd

[2] Çakır, S., & Kesler, M. (2012). Bilgisayar güvenliğini tehdit eden virüsler ve antivirüs yazılımları. 14. Akademik Bilişim Konferansı, 468–476. Retrieved from http://ab.org.tr/ab12/bildiri/82.pdf

[3] ŞAHİN, Yusuf Levent. "İNTERNET’TE GÜVENLİK VE SALDIRI SEZME SİSTEMLERİ," Yüksek Lisans Tezi, Fen Bilimleri Enstitüsü, Bilgisayar Mühendisliği-Bilişim Ana Bilim Dalı, Ağustos-2005.

[4] http://www.pcstats.com/articleview.cfm?articleid=1450&page=4.

[5] file:///C:/Users/Lenovo/Downloads/8.%20hafta%20(2).pdf

[6] https://www.eset.com/tr/antivirus-software/

[7] SAKA, Y., Bilgisayar ağ güvenliği ve şifreleme, Muğla Üniversitesi, Muğla, (2000).

[8] https://www.iienstitu.com/blog/kriptografi-nedir-teknikleri-nelerdir

[9] KARAAHMETOĞLU, O., İnternet güvenliği kavramları ve teknolojileri, İstanbul Teknik Üniversitesi, İstanbul, (2001). 

