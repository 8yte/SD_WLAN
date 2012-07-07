/** @file wlan_wapi.h
 *
 *  @brief wapi functions and type declarations 
 *    
 *  Copyright (C) 2008-2009, Marvell International Ltd.
 *     
 *  This software file (the "File") is distributed by Marvell International 
 *  Ltd. under the terms of the GNU General Public License Version 2, June 1991 
 *  (the "License").  You may use, redistribute and/or modify this File in 
 *  accordance with the terms and conditions of the License, a copy of which 
 *  is available along with the File in the gpl.txt file or by writing to 
 *  the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 
 *  02111-1307 or on the worldwide web at http://www.gnu.org/licenses/gpl.txt.
 *
 *  THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE EXPRESSLY DISCLAIMED.  The License provides additional details about 
 *  this warranty disclaimer.
 *
 */
/*************************************************************
Change Log:
    

************************************************************/

#ifndef __WAPI_H__
#define __WAPI_H__

/** PKT type 802.11 */
#define	PKT_TYPE_802DOT11	        5
/** 802.11 pkt type data */
#define	IEEE80211_TYPE_DATA			0x0008
/** Frame control: To DS */
#define	IEEE80211_FC_TODS           0x0100
/** Frame control: From DS */
#define	IEEE80211_FC_FROMDS         0x0200
/** Frame control: More Flag */
#define	IEEE80211_MORE_FLAG         0x0400
/** Frame control: Retry */
#define	IEEE80211_RETRY             0x0800
/** Frame control: PROTECT */
#define	IEEE80211_FC_PROTECT        0x4000

/** Frame control: Sub Type */
#define IEEE80211_SUBTYPE_QOS       0x0080
/** wapi protocol ether type */
#define WAPI_PKT                    0xb488

/** wapi protocol Tx frag min size */
#define WAPI_FRAG_MIN_SIZE          512
/** wapi protocol Tx max frag number  */
#define MAX_FRAGMENT_NUM            6
/** FCS Size  */
#define FCS_SIZE                     4
/** IEEE80211 Header Size  */
#define IEEE80211_HEADER_SIZE       24
/** IEEE80211 Qos Field Size  */
#define QOS_CTRL_SIZE                2
/** Round Key Size */
#define RK_SIZE                     32
/** Is Group Address */
#define IS_GROUP(macaddr)          ((*(u8*)macaddr & 0x01) == 0x01)

/** Round Key */
typedef u32 round_key[32];

/** PN size */
#define PN_SIZE                     16
/** MIC size */
#define MIC_SIZE                    16

/** PN unicast init */
#define PN_UNICAST_INIT                 0x5C365C36

/** Packet Type: First fragment packet */
#define PKT_FRAG_START     1
/** Packet Type: Fragment packet */
#define PKT_FRAG           2
/** Packet Type: Last fragment packet */
#define PKT_FRAG_LAST      3
/** Packet Type: Nomal packet */
#define PKT_NO_FRAG        4
/** Packet Type: Drop this packet */
#define PKT_DROP           5

/** wlan_802_11_header */
typedef struct _wlan_802_11_header
{
    /** Frame Control */
    u16 FrmCtl;
    /** Duration ID */
    u16 DurationId;
    /** Address1 */
    WLAN_802_11_MAC_ADDRESS Addr1;
    /** Address2 */
    WLAN_802_11_MAC_ADDRESS Addr2;
    /** Address3 */
    WLAN_802_11_MAC_ADDRESS Addr3;
    /** Sequence Control */
    u16 SeqCtl;
    /** Address4 */
    WLAN_802_11_MAC_ADDRESS Addr4;
} __ATTRIB_PACK__ wlan_802_11_header;

/** llc_header */
typedef struct _llc_header
{
    /** snap */
    u8 snap[6];
    /**  protocol ID */
    u16 protocaolID;
} __ATTRIB_PACK__ llc_header;

/** wapi_mic_header */
typedef struct _wapi_mic_header
{
    /** Frame Control */
    u16 FrmCtl;
    /** Address 1 */
    WLAN_802_11_MAC_ADDRESS Addr1;
    /** Address 2 */
    WLAN_802_11_MAC_ADDRESS Addr2;
    /** Sequence Control */
    u16 SeqCtl;
    /** Address 3 */
    WLAN_802_11_MAC_ADDRESS Addr3;
    /** Address 4 */
    WLAN_802_11_MAC_ADDRESS Addr4;
    /** Key Idx */
    u8 KeyIdx;
    /** Reserved */
    u8 Reserved;
    /** Length */
    u16 Len;
} __ATTRIB_PACK__ wapi_mic_header;

/** wapi_qos_mic_header */
typedef struct _wapi_qos_mic_header
{
    /** Frame Control */
    u16 FrmCtl;
    /** Address 1 */
    WLAN_802_11_MAC_ADDRESS Addr1;
    /** Address 2 */
    WLAN_802_11_MAC_ADDRESS Addr2;
    /** Sequence Control */
    u16 SeqCtl;
    /** Address 3 */
    WLAN_802_11_MAC_ADDRESS Addr3;
    /** Address 4 */
    WLAN_802_11_MAC_ADDRESS Addr4;
        /** QoS of packet */
    u16 QoS;
    /** Key Idx */
    u8 KeyIdx;
    /** Reserved */
    u8 Reserved;
    /** Length */
    u16 Len;
    /** Reserved2 */
    u8 Reserved2[14];
} __ATTRIB_PACK__ wapi_qos_mic_header;

/** wapi_header */
typedef struct _wapi_header
{
    /** wlan 802.11 header */
    wlan_802_11_header WlanHdr;
    /** Key id */
    u8 KeyIdx;
    /** Reserved */
    u8 Reserved;
    /** PN */
    u8 PN[PN_SIZE];
} __ATTRIB_PACK__ wapi_header;

/** wapi_frag_header */
typedef struct _wapi_frag_hdr
{
    /** Frame Control */
    u16 FrmCtl;
    /** Frame length */
    u16 FragPktLen;
    /** PN */
    u8 PN[PN_SIZE];
} __ATTRIB_PACK__ wapi_frag_hdr;

/** process rx wapi pkt */
int wlan_process_rx_wapi_pkt(wlan_private * priv, struct sk_buff *skb,
                             RxPacketHdr_t * pRxPkt, RxPD * pRxPD);
/** prepare tx wapi pkt */
void wlan_prepare_tx_wapi_pkt(wlan_adapter * Adapter, wapi_header * pWapiHdr,
                              TxPD * pLocalTxPD, struct sk_buff *skb,
                              u8 * DestAddr, u8 insert8023Bytes, u16 eth_type,
                              u8 FragCnt, u16 FragThreshold, u16 LastPktLen);
u16 wlan_get_wapi_fragment_size(wlan_adapter * Adapter, u16 TxPktLength,
                                u8 * FragCnt, u16 * FragThreshold,
                                u16 * LastPktLen);

#endif
