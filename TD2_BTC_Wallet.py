from copyreg import constructor
from encodings import utf_8
import secrets
import hashlib
from tabnanny import check


def menu() :
    print("What do you want to do ?")
    print("1: create a seed:")
    print("2:")    
    choice = input("what is your choice ?")

    if choice =="1":
        print("create a seed")
    if choice == "2":
        print("choice 2")
        
def conv_bin(n):
    """Convertit un nombre en binaire sans que l'on ai le "0b" en début de nombre"""
    q = -1
    res = ''
    while q != 0:
        q = n // 2
        r = n % 2
        res = str(r) + res
        n = q
    return res

def create_entropy():
    """Créer un entier aléatoire pouvant servir de seed à un wallet de façon sécurisée"""
    entropy = secrets.randbits(128)
    while(len(conv_bin(entropy)) !=128):
        entropy = secrets.randbits(128)
    return entropy


def binary_seed():
    """Représenter cette seed en binaire et le découper en lot de 11 bits"""
    entropy = create_entropy()
    binary_entropy=conv_bin(entropy)
    print(binary_entropy)
    checksum = conv_bin(int(hashlib.sha256(binary_entropy.encode("utf-8")).hexdigest(),base =16))[0:4]
    total_entropy = binary_entropy + checksum
    print(total_entropy)
    result = []
    mot =""
    for i in range(1,len(str(total_entropy))+1):
        mot+=str(total_entropy)[i-1]
        if i%11==0 :
            result.append(mot)
            mot =""
    result.append(mot)
    
    for i in range(12):
        print(result[i])
        print(int(result[i],2))
    tab_of_words = []
    with open("words.txt","r") as file:
        tab_of_words = list(file)
    for i in range(len(tab_of_words)):
        tab_of_words[i] = tab_of_words[i].rstrip("\n")
    
    seed_mnemotechnique = ""
    for i in range(12):
        seed_mnemotechnique += tab_of_words[int(result[i],2)] + " "
    print(seed_mnemotechnique)
    

if __name__=='__main__':
    binary_seed()