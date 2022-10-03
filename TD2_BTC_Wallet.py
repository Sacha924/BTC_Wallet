import secrets, hashlib, sys, codecs, ecdsa

tab_of_BIP39_words = []
with open("words.txt","r") as file:
    tab_of_BIP39_words = list(file)
for i in range(len(tab_of_BIP39_words)):
    tab_of_BIP39_words[i] = tab_of_BIP39_words[i].rstrip("\n")

def padd_binary(bin_str: str, size: int) -> str:
    """
    Pads a binary string with zeros to the left
    :param bin_str: binary string to pad
    :param size: size of the padded string
    :return: padded binary string
    """
    for _ in range(size - len(bin_str)):
        bin_str = '0' + bin_str
    return bin_str

def byte_to_binary(b: bytes, size: int) -> str:
    """
    Converts a byte to a binary string
    :param byte: byte to convert
    :param size: size of the binary string
    :return: binary string
    """
    order = -1 if sys.byteorder == 'little' else 1
    bin_n = bin(int.from_bytes(b, byteorder='big'))[2:]
    return padd_binary(bin_n, size)

def create_entropy():
    """Créé un entier aléatoire pouvant servir de seed à un wallet de façon sécurisée"""
    entropy = secrets.token_bytes(16)
    binEntropy = byte_to_binary(entropy,128)
    print("\nL'entier aléatoire généré pouvant servir de seed est :\nvaleur en byte",entropy, "\nvaleur numérique : ",int(binEntropy,2))
    return binEntropy, byte_to_binary(hashlib.sha256(entropy).digest(),256)
    #La deuxième valeur retournée correspond à notre hash dont on va extraire les 4 premiers bits

def create_binary_seed():
    binEntropy, hash_ = create_entropy()
    entropy_132bits = binEntropy + hash_[:4]
    print("\nL'entier aléatoire, une fois convertir en binaire est : ", binEntropy)
    print("\nOn y ajoute le checksum et on obtient 132 bits : ",entropy_132bits)
    tabOf11Bits= []
    mot=""
    for i in range(1,len(str(entropy_132bits))+1):
        mot+=str(entropy_132bits)[i-1]
        if i%11==0 :
            tabOf11Bits.append(mot)
            mot =""
    print("\nOn séparer cette entropie de 132 bits en 12 valeurs de 11 bits chacun : ")
    for i in range(1, len(tabOf11Bits)+1):
        print(i,tabOf11Bits[i-1], sep= ' : ')
     
    return tabOf11Bits
    
    
def create_mnemonic_seed():
    tabOf11Bits = create_binary_seed()
    mnemonic_seed = ""
    for i in range(12):
        mnemonic_seed += tab_of_BIP39_words[int(tabOf11Bits[i],2)] + " "
    print("\nEnfin, on reconvertit les valeurs contenant 11 bits et on les associe au mot, afin de former notre seed mnémonique :\n"+mnemonic_seed,"\n")
    return mnemonic_seed

def import_mnemonic_seed():
    
    mnemonic_seed = []
    for i in range(12):
        mnemonic_seed.append(input("Entrer le mot "+str(i)+" de votre seed mnémonique : "))
    if (len(mnemonic_seed)!=12):
        print("Seed phrase lengh is not 12")
        return None
    else:
        number = []

        #boucle pour trouver les valeurs numériques associées aux mots
        with open("words.txt",'r') as file:
            list_file = list(file)
            for i in range(len(mnemonic_seed)):
                for j in range(len(list_file)):
                    if (str(mnemonic_seed[i]+"\n")==list_file[j]):
                        tempo = str(bin(j)[2:])        
                        number.append(tempo)
                    else :
                        print("mot "+str(mnemonic_seed[i])+" n'est pas un mot mnémonique")
                        return None

        #boucle pour ajouter des 0 devant les bits pour atteindre une longueur de 11 bits
        for i in range(len(number)):
            if(int(len(number[i])<11)):
                for j in range(11-len(number[i])):
                    number[i] = "0"+number[i]
        
            
        
        number_without_hash=''.join(number)
        number_without_hash = number_without_hash[:-4]
        print("128 bits entropy : "+str(number_without_hash))
        hash = number[11][7:11]
        print("checksum : "+str(hash))
        return ''.join(number) 


def get_MPrivK_and_CC():
    """Extrait la master private key et le chain code"""
    mnemonic_seed = create_mnemonic_seed()
    print("\n------------------------------------------------------------ Master Private Key ------------------------------------------------------------\n")
    hashSha512 = hashlib.sha512( mnemonic_seed.encode("utf-8") ).hexdigest()
    mPrivK, chainCode = hashSha512[:len(hashSha512)//2],hashSha512[len(hashSha512)//2:]
    print("Hash Sha512 : " + hashSha512, "\nMaster private key : " + mPrivK,"\nChain Code : " + chainCode)
    return mPrivK, chainCode

def get_MpubK():
    """Extrait la master public key"""
    mPrivK, cc = get_MPrivK_and_CC()
    print("\n------------------------------------------------------------ Master Public Key ------------------------------------------------------------\n")
    privK_bytes = codecs.decode(mPrivK, 'hex')
    pubK_bytes = (ecdsa.SigningKey.from_string(privK_bytes, curve=ecdsa.SECP256k1).verifying_key).to_string()
    pubK_hex = codecs.encode(pubK_bytes, 'hex')
    public_key = (b'04' + pubK_hex).decode("utf-8")
    pubK_beginning = ""
    if (ord(bytearray.fromhex(public_key[-2:])) % 2 == 0):
        pubK_beginning = '0x02'
    else:
        pubK_beginning = '0x03'
      
    masterPublicKey =  pubK_beginning + public_key[2:66]
    print("Master Public Key : " + masterPublicKey)
    return masterPublicKey, cc


    
def get_child_key_n(index):
    """Extrait la child key index n"""
    pb_key,cc = get_MpubK()
    print("\n---------------------------------------------------------------- Child Key ----------------------------------------------------------------\n")
    index_bin = padd_binary(format(index,'b'),32) 
    NewhashSha512 = ""
    if(index ==0): NewhashSha512 = hashlib.sha512( (pb_key + cc).encode("utf-8") ).hexdigest() 
    else : NewhashSha512 = hashlib.sha512( (pb_key + cc + index_bin).encode("utf-8") ).hexdigest() 
    childprivatekey,childchaincode = NewhashSha512[:len(NewhashSha512)//2],NewhashSha512[len(NewhashSha512)//2:]
    print("Child Private Key : " + childprivatekey, "\nChild chaincode : " + childchaincode)

    
if __name__=='__main__':
    print("What do you want to do ?\n1: Créer un entier aléatoire pouvant servir de seed à un wallet de façon sécurisée \n2 : Représenter cette seed en binaire et le découper en lot de 11 bits \n3 : Attribuer à chaque lot un mot selon la liste BIP 39 et afficher la seed en mnémonique \n4 : Permettre l’import d’une seed mnémonique\n5 : Extraire la master private key et le chain code \n6 : Extraire la master public key\n7 : Générer un clé enfant \n8 : Générer une clé enfant à l’index N")
    choice = int(input("\nWhat is your choice ?\n"))

    if(choice == 1):
        create_entropy()
    elif(choice == 2):
        create_binary_seed()
    elif(choice == 3):
        create_mnemonic_seed()
    elif(choice == 4):
        import_mnemonic_seed()
    elif(choice == 5):
        get_MPrivK_and_CC()
    elif (choice == 6):
        get_MpubK()
    elif (choice == 7):
        index = 0
        get_child_key_n(index)
    elif (choice == 8):
        index = int(input("Index de la child key n : "))
        get_child_key_n(index)