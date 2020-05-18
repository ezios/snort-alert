#coding utf-8
import time
import events
import pickle
import os
import string
from gmail import create_message,send_message
from info import mail_from,mail_to,level


def send_alert(message_text,subject):
    for to in mail_to:    
        message = create_message(mail_from,to,subject,message_text)
        send_message("me", message)



def strings(payload):
    try: 
        binpayload = bytearray.fromhex(payload)
        result=""
        for c  in binpayload:
            str_c = chr(c)
            if str_c in string.printable[0:95]:
                result += str_c
        return result
    except:
        return "Echec conversion en caractère lisile"

def forge_message(alert):
    if alert["Payload"]!= 0:
                PayloadStrings = strings(alert["Payload"])
    else:
                alert["Payload"] = "Vide"
                PayloadStrings = "Vide"
    message = """Id :  {} 
    Temps : {} 
    Signature Alerte : {} 
    Reference évenement : {}
    Description : {} 
    Protocole réseau : {}
    Adresse source et port source : {} : {} 
    Adresse destination et port de destianation : {} : {} 
    Contenu du paquet : 
         Hexadecimal : {}   
         Ascii :  {} \n\n """.format(alert["EventId"],\
    alert["EventTimeStamp"],\
    alert["Alert"],\
    alert["ref"],
    alert["AlertClass"],\
    alert["Protocol"],
    alert["SourceIP"],alert["SourcePort"],\
    alert["DestinationIP"],alert["DestinationPort"],\
    alert["Payload"][0:40],\
    PayloadStrings)
    return message


def getoldevents():
    if os.path.exists('previous.pickle'):
            with open('previous.pickle', 'rb') as f:
                old_events = pickle.load(f)
                return old_events
    return None

previous = getoldevents()

print("[+] Swatcher up" )
while True:
    # Nombre d'evenement qui se sont déroulés pendant le temps d'attente
    diff = events.LastEvent() - max(previous)
    # On recupere c'est n dernier éléments dans la base de donnée, en filtrant le niveau qu'on souhaite 
    alerts = events.data(diff,level)
    print(diff," events since the last sent message.")
    #On parcours les lignes des évenements
    for alert in alerts:
        #Si l'évenement n'a pas été déjà envoyé , on l'envoi
        if alert["EventId"] not in previous:
            print("--------New Alert-------",alert["EventId"])
            
    # ecriture du message d'alerte
    
            if alert["Priority"] == 0:
                subject= "Alerte Niveau Maximale "
            if alert["Priority"] == 1:
                subject= "Alerte Niveau Elevé"
            if alert["Priority"] == 2:
                subject= "Protocole non respecté"
            previous.append(alert["EventId"])

            message = forge_message(alert)

            #ici on sauvegarde que le message a été envoyé
            with open('previous.pickle',"wb") as p:
                pickle.dump(previous,p)
            send_alert(message,subject)
    time.sleep(20)  
    print("Waiting...")           