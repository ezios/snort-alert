import mysql.connector
from dbinfo import *
ids_db = mysql.connector.connect(host=db_host,user=db_user,
                                    passwd=db_password,
                                    database=db_remote_database
        )

def LastEvent():
        global ids_db
        db = ids_db.cursor(dictionary=True)
        db.execute("""SELECT event.cid as 'Id' FROM event
        ORDER BY Id DESC
        LIMIT 1""")
        return db.fetchall()[0]["Id"]
 


def data(number_of_rows,level):
    global ids_db
    db = ids_db.cursor(dictionary=True)
    db.execute("""  SELECT event.cid as 'EventId',
                    signature.sig_priority as 'Priority',
                    signature.sig_name as 'Alert',
                    event.signature as 'ref',
                    sig_class.sig_class_name as 'AlertClass',
                    iphdr.ip_proto as 'Protocol',
                    INET_NTOA(iphdr.ip_src) as 'SourceIP',
                    tcphdr.tcp_sport as 'SourcePort',
                    INET_NTOA(iphdr.ip_dst) as 'DestinationIP',
                    tcphdr.tcp_dport as 'DestinationPort',
                    event.timestamp as 'EventTimeStamp',
                    data.data_payload as 'Payload'
                FROM event
                    JOIN iphdr ON event.cid=iphdr.cid
                    JOIN tcphdr ON event.cid=tcphdr.cid
                    JOIN signature ON event.signature=signature.sig_id
                    JOIN sig_class ON signature.sig_class_id=sig_class.sig_class_id
                    JOIN data ON event.cid=data.cid
                    WHERE signature.sig_priority <={0}
                UNION
                SELECT event.cid as 'EventId',
                    signature.sig_priority as 'Priority',
                    signature.sig_name as 'Alert',
                    event.signature as 'ref',
                    sig_class.sig_class_name as 'AlertClass',   
                    iphdr.ip_proto as 'Protocol',
                    INET_NTOA(iphdr.ip_src) as 'SourceIP',
                    udphdr.udp_sport as 'SourcePort',
                    INET_NTOA(iphdr.ip_dst) as 'DestinationIP',
                    udphdr.udp_dport as 'DestinationPort',
                    event.timestamp as 'EventTimeStamp',
                    data.data_payload as 'Payload'
                FROM event
                    JOIN iphdr ON event.cid=iphdr.cid
                    JOIN udphdr ON event.cid=udphdr.cid
                    JOIN signature ON event.signature=signature.sig_id
                    JOIN sig_class ON signature.sig_class_id=sig_class.sig_class_id
                    JOIN data ON event.cid=data.cid
                    WHERE signature.sig_priority <= {0}
                UNION
                SELECT event.cid as 'EventId',
                    signature.sig_priority as 'Priority',
                    signature.sig_name as 'Alert',
                    event.signature as 'ref',
                    sig_class.sig_class_name as 'AlertClass',
                    iphdr.ip_proto as 'Protocol',
                    INET_NTOA(iphdr.ip_src) as 'SourceIP',
                    icmphdr.icmp_type as 'SourcePort',
                    INET_NTOA(iphdr.ip_dst) as 'DestinationIP',
                    icmphdr.icmp_type as 'DestinationPort',
                    event.timestamp as 'EventTimeStamp',
                    data.data_payload as 'Payload'
                FROM event
                    JOIN iphdr ON event.cid=iphdr.cid
                    JOIN icmphdr ON event.cid=icmphdr.cid
                    JOIN signature ON event.signature=signature.sig_id
                    JOIN sig_class ON signature.sig_class_id=sig_class.sig_class_id
                    JOIN data ON event.cid=data.cid
                    WHERE signature.sig_priority <= {0}
                    ORDER BY EventId DESC
                    LIMIT {1} """.format(level,number_of_rows))


    
    return db.fetchall()

