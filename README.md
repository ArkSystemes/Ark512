# Ark512
(Linux|Windows) Dirty base d'un ransomware avec dump du MBR windows et remplacement par Loot$$Loader MBR - But Educatif


### FR
- Utilisation du module mmap de python pour gagner en rapidite de lecture en mappant les fichiers directement en memoire physique.
- Chiffrement AES256 mode CBC (a passer en mod GCM) avec clef aleatoire.
- On chiffre uniquement les 512 premier octet des fichiers pour gagner en rapidite.
- On fait une sauvegarde du MBR de windows.
- On ecrit notre MBR au debut du disque principal.
- A executer en Administrator. 

### EN
- Using mmap python module for increase speed of reading files by mapping it directly to physical memory
- Encryption with AES256 mode CBC (will use mode GCM soon) with random key
- Encrypt only the first 512 bytes of file for increase speed batching
- Backup of original windows MBR
- Write our MBR at the beginning of the main drive
- Run as Administrator
