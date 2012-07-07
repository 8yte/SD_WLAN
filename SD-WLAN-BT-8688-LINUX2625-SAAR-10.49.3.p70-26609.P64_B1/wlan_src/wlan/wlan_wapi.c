/** @file wlan_wapi.c
  * @brief This file contains the functions for wapi support
  * 
  * Copyright (C) 2008-2009, Marvell International Ltd.
  *   
  * This software file (the "File") is distributed by Marvell International 
  * Ltd. under the terms of the GNU General Public License Version 2, June 1991 
  * (the "License").  You may use, redistribute and/or modify this File in 
  * accordance with the terms and conditions of the License, a copy of which 
  * is available along with the File in the gpl.txt file or by writing to 
  * the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 
  * 02111-1307 or on the worldwide web at http://www.gnu.org/licenses/gpl.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE 
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE 
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about 
  * this warranty disclaimer.
  *
  */
/********************************************************
Change log:
        12/16/08 Create this file
	
********************************************************/

#include <linux/string.h>
#include "wlan_headers.h"
#include "mcypt.h"

/********************************************************
		Local Variables
********************************************************/

/********************************************************
		Global Variables
********************************************************/

/********************************************************
		Local Functions
********************************************************/
/**
 *  @brief This function get the avalible key for rx packet
 * 
 *  @param Adapter      a pointer to wlan_adapter structure
 *  @param KeyIdx       key index  
 *  @param unicast      get unicast key or mulitcast key
 *  @return 	        wapi_key or NULL
 */
wapi_key *
wapi_get_key(wlan_adapter * Adapter, u8 KeyIdx, u8 unicast)
{
    if (unicast) {
        if (KeyIdx == Adapter->cur_wapi_key.Wapi_uni_key.keyid)
            return &Adapter->cur_wapi_key.Wapi_uni_key;
        if (KeyIdx == Adapter->old_wapi_key.Wapi_uni_key.keyid)
            return &Adapter->old_wapi_key.Wapi_uni_key;
    } else {
        if (KeyIdx == Adapter->cur_wapi_key.Wapi_grp_key.keyid)
            return &Adapter->cur_wapi_key.Wapi_grp_key;
        if (KeyIdx == Adapter->old_wapi_key.Wapi_grp_key.keyid)
            return &Adapter->old_wapi_key.Wapi_grp_key;
    }
    return NULL;
}

/**
 *  @brief This function handle the packet decryption
 * 
 *  @param Priority     priority of the packet  
 *  @param pRxBuffer    A pointer to receive buffer
 *  @param Length       Packet length
 *  @param rk           A pointer to round key structure
 *  @param mic_rk       A pointer to MIC round key structure
 *  @return 	        TRUE /FALSE
 */
int
wapi_decrypt_rx_packet(u16 Priority, u8 * pRxBuffer, u32 Length, round_key * rk,
                       round_key * mic_rk)
{
    wlan_802_11_header *pWlanHeader;
    wapi_header *pWapiHdr;
    u8 *pData;
    u8 *pMic;
    u8 IV[PN_SIZE], MicVerify[MIC_SIZE], MicInPkt[MIC_SIZE];
    u8 QosEnable;
    wapi_mic_header WapiMicHdr;
    wapi_qos_mic_header WapiQosHdr;
    u16 DataLen, MicLen, pad;
    u32 i;

    ENTER();
    pWlanHeader = (wlan_802_11_header *) pRxBuffer;
    pWapiHdr = (wapi_header *) pRxBuffer;

    HEXDUMP("Data Encrypted  ", (u8 *) pWlanHeader, Length);

    for (i = 0; i < 16; i++)
        IV[15 - i] = pWapiHdr->PN[i];

    pData = (u8 *) (pRxBuffer + sizeof(wapi_header));
    DataLen = (u16) (Length - sizeof(wapi_header));

    // decrypt and store back input buffer.
    mencrypt_decrypt(IV, pData, DataLen, (u32 *) rk, pData);

    HEXDUMP("Data Decrypted  ", (u8 *) pWlanHeader, Length);

    pMic = (u8 *) ((u32) pRxBuffer + Length - MIC_SIZE);

    // copy to MicInPkt for verification
    memcpy(MicInPkt, pMic, MIC_SIZE);

    HEXDUMP("MIC", (u8 *) pMic, MIC_SIZE);

    QosEnable = (pWlanHeader->FrmCtl & IEEE80211_SUBTYPE_QOS) ? 1 : 0;

    if (QosEnable) {
        // verify MIC
        memset((void *) &WapiQosHdr, 0x00, sizeof(WapiQosHdr));
        WapiQosHdr.FrmCtl = pWapiHdr->WlanHdr.FrmCtl;
        WapiQosHdr.FrmCtl &= ~(0x3870); // b4,5,6,11,12,13 =0
        WapiQosHdr.FrmCtl |= 0x4000;    // b14 = 1

        // copy Addr1,Addr2
        memcpy((void *) WapiQosHdr.Addr1, (void *) (pWlanHeader->Addr1),
               2 * ETH_ALEN);

        // copy Addr3
        memcpy((void *) WapiQosHdr.Addr3, (void *) (pWlanHeader->Addr3),
               ETH_ALEN);
        memcpy((void *) WapiQosHdr.Addr4, (void *) (pWlanHeader->Addr4),
               ETH_ALEN);

        /* Sequence control field bit 4 to bit 15 are zero */
        WapiQosHdr.SeqCtl = pWlanHeader->SeqCtl;
        WapiQosHdr.SeqCtl &= 0x000F;    // bit4-15 =0

        // copy Priority
        WapiQosHdr.QoS |= Priority;

        WapiQosHdr.KeyIdx = pWapiHdr->KeyIdx;
        MicLen = (u16) (Length - (sizeof(wapi_header) + MIC_SIZE));
        WapiQosHdr.Len = ((MicLen >> 8) | (MicLen << 8));

        PRINTM(DATA, "Priority=0x%04x QosEnable=%d\n", Priority, QosEnable);
        HEXDUMP("WapiQosHdr:", (u8 *) & WapiQosHdr, sizeof(WapiQosHdr));
    } else {
        WapiMicHdr.FrmCtl = pWapiHdr->WlanHdr.FrmCtl;
        WapiMicHdr.FrmCtl &= ~(0x3870); // b4,5,6,11,12,13 =0
        WapiMicHdr.FrmCtl |= 0x4000;    // b14 = 1
        // copy Addr1,Addr2
        memcpy((void *) WapiMicHdr.Addr1, (void *) (pWlanHeader->Addr1),
               2 * ETH_ALEN);
        // copy Addr3
        memcpy((void *) WapiMicHdr.Addr3, (void *) (pWlanHeader->Addr3),
               ETH_ALEN);
        memcpy((void *) WapiMicHdr.Addr4, (void *) (pWlanHeader->Addr4),
               ETH_ALEN);

        /* Sequence control field bit 4 to bit 15 are zero */
        WapiMicHdr.SeqCtl = pWlanHeader->SeqCtl;
        WapiMicHdr.SeqCtl &= 0x000F;    // bit4-15 =0

        WapiMicHdr.KeyIdx = pWapiHdr->KeyIdx;
        WapiMicHdr.Reserved = 0;
        MicLen = (u16) (Length - (sizeof(wapi_header) + MIC_SIZE));
        WapiMicHdr.Len = ((MicLen >> 8) | (MicLen << 8));
        PRINTM(DATA, "Priority=0x%04x QosEnable=%d\n", Priority, QosEnable);
    }

    pad = MicLen & 0xF;
    if (pad) {
        pad = 16 - pad;         // padding to 16bytes alignment
        MicLen += pad;
        // fill zero
        memset(pMic, 0, pad);
    }

    if (QosEnable) {
        mgen_mic(IV, (u8 *) & WapiQosHdr, sizeof(wapi_qos_mic_header),
                 (u8 *) (pRxBuffer + sizeof(wapi_header)), MicLen,
                 (u32 *) mic_rk, MicVerify);
    } else {
        mgen_mic(IV, (u8 *) & WapiMicHdr, sizeof(wapi_mic_header),
                 (u8 *) (pRxBuffer + sizeof(wapi_header)), MicLen,
                 (u32 *) mic_rk, MicVerify);
    }

    if (memcmp(MicInPkt, MicVerify, MIC_SIZE)) {
        PRINTM(ERROR, "##### MIC error ###########\n");
        DBG_HEXDUMP(DAT_D, "Caculated MIC:", MicVerify, MIC_SIZE);
        DBG_HEXDUMP(DAT_D, "MIC in Pkt:", MicInPkt, MIC_SIZE);
        LEAVE();
        return FALSE;
    }
    PRINTM(INFO, "Received a frame without error...\n");
    LEAVE();
    return TRUE;
}

/**
 *  @brief This function handle the packet encryption
 *  
 *  @param QosEnable    QosEnable flag
 *  @param Priority     packet priority
 *  @param pTxBuffer    A pointer to tx buffer
 *  @param Length       packet length
 *  @param rk           A pointer to round key structure
 *  @param mic_rk       A pointer to MIC round key structure
 *  @return 	        N/A
 */
void
wapi_encrypt_tx_packet(u8 QosEnable, u16 Priority, u8 * pTxBuffer, u32 Length,
                       round_key * rk, round_key * mic_rk)
{
    u8 IV[MIC_SIZE], Mic[MIC_SIZE];
    u8 *pData;
    u8 *pMic;
    wlan_802_11_header *pWlanHdr;
    wapi_header *pWapiHdr;
    wapi_mic_header WapiMicHdr;
    wapi_qos_mic_header WapiQosHdr;
    u32 i;
    u16 DataLen, MicLen, pad;

    ENTER();

    pWlanHdr = (wlan_802_11_header *) pTxBuffer;
    pWapiHdr = (wapi_header *) pTxBuffer;

    if (QosEnable) {
        memset((void *) &WapiQosHdr, 0x00, sizeof(WapiQosHdr));
        /* compose WAPI header */
        WapiQosHdr.FrmCtl = pWlanHdr->FrmCtl;
        // set frame control bits 4,5,6,11,12,13 to zero and make bit14= 1 
        WapiQosHdr.FrmCtl &= ~(0x3870); // b4,5,6,11,12,13 =0
        WapiQosHdr.FrmCtl |= 0x4000;    // b14 = 1

        // copy Addr1,Addr2
        memcpy((void *) WapiQosHdr.Addr1, (void *) (pWlanHdr->Addr1),
               2 * ETH_ALEN);
        // copy Addr3
        memcpy((void *) WapiQosHdr.Addr3, (void *) (pWlanHdr->Addr3), ETH_ALEN);
        // clear Addr4
        memcpy((void *) WapiQosHdr.Addr4, (void *) (pWlanHdr->Addr4), ETH_ALEN);
        // copy Priority
        WapiQosHdr.QoS |= Priority;
        // copy SeqCtl
        WapiQosHdr.SeqCtl = pWlanHdr->SeqCtl;
        // Sequence control field bit 4 to bit 15 are zero
        WapiQosHdr.SeqCtl &= 0x000F;

        WapiQosHdr.KeyIdx = pWapiHdr->KeyIdx;
        WapiQosHdr.Reserved = 0;
        MicLen = (u16) (Length - sizeof(wapi_header));
        WapiQosHdr.Len = ((MicLen >> 8) | (MicLen << 8));
        PRINTM(DATA, "Priority=0x%04x QosEnable=%d\n", Priority, QosEnable);
        HEXDUMP("WapiQosHdr:", (u8 *) & WapiQosHdr, sizeof(WapiQosHdr));
    } else {
        /* compose WAPI header */
        WapiMicHdr.FrmCtl = pWlanHdr->FrmCtl;
        // set frame control bits 4,5,6,11,12,13 to zero and make bit14= 1 
        WapiMicHdr.FrmCtl &= ~(0x3870); // b4,5,6,11,12,13 =0
        WapiMicHdr.FrmCtl |= 0x4000;    // b14 = 1

        // copy Addr1,Addr2
        memcpy((void *) WapiMicHdr.Addr1, (void *) (pWlanHdr->Addr1),
               2 * ETH_ALEN);
        // copy Addr3
        memcpy((void *) WapiMicHdr.Addr3, (void *) (pWlanHdr->Addr3), ETH_ALEN);
        // clear Addr4
        memcpy((void *) WapiMicHdr.Addr4, (void *) (pWlanHdr->Addr4), ETH_ALEN);
        // copy SeqCtl
        WapiMicHdr.SeqCtl = pWlanHdr->SeqCtl;
        // Sequence control field bit 4 to bit 15 are zero
        WapiMicHdr.SeqCtl &= 0x000F;

        WapiMicHdr.KeyIdx = pWapiHdr->KeyIdx;
        WapiMicHdr.Reserved = 0;
        MicLen = (u16) (Length - sizeof(wapi_header));
        WapiMicHdr.Len = ((MicLen >> 8) | (MicLen << 8));
        PRINTM(DATA, "Priority=0x%04x QosEnable=%d\n", Priority, QosEnable);
    }
    // copy IV
    for (i = 0; i < 16; i++)
        IV[15 - i] = pWapiHdr->PN[i];

    PRINTM(INFO, "Tx Test 2 encrypt: TxPktLength = %d pWapiHdr = %p\n", Length,
           pWapiHdr);
    PRINTM(INFO, "Tx Test 2 encrypt: pTxBuffer = %p Length = %d\n", pTxBuffer,
           Length);
    HEXDUMP("IV        ", (u8 *) IV, 16);
    if (QosEnable) {
        HEXDUMP("ICD with QoS Header", (u8 *) & WapiQosHdr,
                sizeof(wapi_qos_mic_header));
    } else {
        HEXDUMP("ICD Header", (u8 *) & WapiMicHdr, sizeof(wapi_mic_header));
    }

    pMic = (u8 *) ((u32) pTxBuffer + Length);

    pad = MicLen & 0xF;
    if (pad) {
        pad = 16 - pad;         // padding to 16bytes alignment
        MicLen += pad;
        // fill zero
        memset(pMic, 0, pad);
    }

    pData = (u8 *) (pTxBuffer + sizeof(wapi_header));
    DataLen = (u16) (Length - sizeof(wapi_header) + MIC_SIZE);

    PRINTM(INFO, "Tx Test 2.5 encrypt: pData = %p DataLen = %d\n", pData,
           DataLen);
    HEXDUMP("Plain Text", pTxBuffer, Length + MIC_SIZE);

    if (QosEnable) {
        mgen_mic(IV, (u8 *) & WapiQosHdr, sizeof(wapi_qos_mic_header),
                 (u8 *) pData, MicLen, (u32 *) mic_rk, (u8 *) Mic);
    } else {
        mgen_mic(IV, (u8 *) & WapiMicHdr, sizeof(wapi_mic_header), (u8 *) pData,
                 MicLen, (u32 *) mic_rk, (u8 *) Mic);
    }

    HEXDUMP("Mic", (u8 *) Mic, MIC_SIZE);
    memcpy(pMic, Mic, MIC_SIZE);
    mencrypt_decrypt(IV, pData, DataLen, (u32 *) rk, pData);
    HEXDUMP("Tx encrypted Out:", (u8 *) pTxBuffer, (Length + MIC_SIZE));
    LEAVE();
}

/**
 *  @brief This function handle the packet encryption
 *  
 *  @param QosEnable    QosEnable flag
 *  @param Priority     packet priority
 *  @param pWapiHdr     A pointer to wapi buffer
 *  @param pTxBuffer    A pointer to tx buffer
 *  @param Length       packet length
 *  @param rk           A pointer to round key structure
 *  @param mic_rk       A pointer to MIC round key structure
 *  @return 	        N/A
 */
void
wapi_encrypt_frag_packet(u8 QosEnable,
                         u16 Priority,
                         wapi_header * pWapiHdr,
                         u8 * pTxBuffer,
                         u32 Length, round_key * rk, round_key * mic_rk)
{
    u8 IV[MIC_SIZE], Mic[MIC_SIZE];
    u8 *pData;
    u8 *pMic;
    wlan_802_11_header *pWlanHdr;
    wapi_frag_hdr *pFragInfo;
    wapi_mic_header WapiMicHdr;
    wapi_qos_mic_header WapiQosHdr;
    u32 i;
    u16 DataLen, MicLen, pad;

    ENTER();

    pWlanHdr = (wlan_802_11_header *) pWapiHdr;
    pFragInfo = (wapi_frag_hdr *) pTxBuffer;

    MicLen = (u16) Length;

    if (QosEnable) {
        memset((void *) &WapiQosHdr, 0x00, sizeof(WapiQosHdr));
        /* compose WAPI header */
        WapiQosHdr.FrmCtl = pWlanHdr->FrmCtl;
        // set frame control bits 4,5,6,11,12,13 to zero and make bit14= 1 
        WapiQosHdr.FrmCtl &= ~(0x3870); // b4,5,6,11,12,13 =0
        WapiQosHdr.FrmCtl |= 0x4000;    // b14 = 1

        // copy Addr1,Addr2
        memcpy((void *) WapiQosHdr.Addr1, (void *) (pWlanHdr->Addr1),
               2 * ETH_ALEN);
        // copy Addr3
        memcpy((void *) WapiQosHdr.Addr3, (void *) (pWlanHdr->Addr3), ETH_ALEN);
        // clear Addr4
        memcpy((void *) WapiQosHdr.Addr4, (void *) (pWlanHdr->Addr4), ETH_ALEN);
        // copy Priority
        WapiQosHdr.QoS |= Priority;
        // copy SeqCtl
        WapiQosHdr.SeqCtl = pWlanHdr->SeqCtl;
        // Sequence control field bit 4 to bit 15 are zero
        WapiQosHdr.SeqCtl &= 0x000F;

        WapiQosHdr.KeyIdx = pWapiHdr->KeyIdx;
        WapiQosHdr.Reserved = 0;
        WapiQosHdr.Len = ((MicLen >> 8) | (MicLen << 8));
    } else {
        /* compose WAPI header */
        WapiMicHdr.FrmCtl = pWlanHdr->FrmCtl;
        // set frame control bits 4,5,6,11,12,13 to zero and make bit14= 1 
        WapiMicHdr.FrmCtl &= ~(0x3870); // b4,5,6,11,12,13 =0
        WapiMicHdr.FrmCtl |= 0x4000;    // b14 = 1

        // copy Addr1,Addr2
        memcpy((void *) WapiMicHdr.Addr1, (void *) (pWlanHdr->Addr1),
               2 * ETH_ALEN);
        // copy Addr3
        memcpy((void *) WapiMicHdr.Addr3, (void *) (pWlanHdr->Addr3), ETH_ALEN);
        // clear Addr4
        memcpy((void *) WapiMicHdr.Addr4, (void *) (pWlanHdr->Addr4), ETH_ALEN);
        // copy SeqCtl
        WapiMicHdr.SeqCtl = pWlanHdr->SeqCtl;
        // Sequence control field bit 4 to bit 15 are zero
        WapiMicHdr.SeqCtl &= 0x000F;

        WapiMicHdr.KeyIdx = pWapiHdr->KeyIdx;
        WapiMicHdr.Reserved = 0;
        WapiMicHdr.Len = ((MicLen >> 8) | (MicLen << 8));
    }
    PRINTM(DATA, "Priority=0x%04x QosEnable=%d\n", Priority, QosEnable);
    if (QosEnable) {
        HEXDUMP("ICD with QoS Header", (u8 *) & WapiQosHdr,
                sizeof(wapi_qos_mic_header));
    } else {
        HEXDUMP("ICD Header", (u8 *) & WapiMicHdr, sizeof(wapi_mic_header));
    }
    // copy IV
    for (i = 0; i < 16; i++)
        IV[15 - i] = pFragInfo->PN[i];

    HEXDUMP("IV        ", (u8 *) IV, 16);

    pMic = (u8 *) (pTxBuffer + Length + sizeof(wapi_frag_hdr));

    pad = MicLen & 0xF;

    if (pad) {
        pad = 16 - pad;         // padding to 16bytes alignment
        MicLen += pad;
        // fill zero
        memset(pMic, 0, pad);
    }

    pData = (u8 *) (pTxBuffer + sizeof(wapi_frag_hdr));
    DataLen = (u16) (Length + MIC_SIZE);

    if (QosEnable) {
        mgen_mic(IV, (u8 *) & WapiQosHdr, sizeof(wapi_qos_mic_header),
                 (u8 *) pData, MicLen, (u32 *) mic_rk, (u8 *) Mic);
    } else {
        mgen_mic(IV, (u8 *) & WapiMicHdr, sizeof(wapi_mic_header), (u8 *) pData,
                 MicLen, (u32 *) mic_rk, (u8 *) Mic);
    }

    HEXDUMP("Mic", (u8 *) Mic, MIC_SIZE);
    memcpy(pMic, Mic, MIC_SIZE);

    mencrypt_decrypt(IV, pData, DataLen, (u32 *) rk, pData);
    HEXDUMP("Tx encrypted Out:", (u8 *) pTxBuffer,
            (Length + MIC_SIZE + sizeof(wapi_frag_hdr)));
    LEAVE();
}

/** 
 *  @brief This function generate 802.3 header
 *
 *  
 *  @param hdrlen  header len
 *  @param data    pointer to data buffer
 *  @param pRxPD   A pointer to RxPD structure of received packet
 *  @return 	   n/a
 */
void
wlan_genhdr_to_8023(u8 hdrlen, u8 * data, RxPD * pRxPD)
{
    wlan_802_11_header Header;
    EthII_Hdr_t *ethHdr = NULL;
    // Allow host to select Ethernet II format rx; default is SNAP format.
    char LLC[3] = { 0xaa, 0xaa, 0x03 };
    u8 convert_to_enetII = 0;

    PRINTM(DATA, "Rx: pktlen=%d offset=%d hdrlen=%d\n", pRxPD->RxPktLength,
           pRxPD->RxPktOffset, hdrlen);

    memcpy((u8 *) & Header, data, sizeof(wlan_802_11_header));

    DBG_HEXDUMP(DAT_D, "Rx 802.11 header", data, hdrlen);

    data += hdrlen;
    pRxPD->RxPktOffset += hdrlen;
    pRxPD->RxPktLength -= hdrlen;

    if (memcmp(data, LLC, sizeof(LLC)) == 0) {
        // Skip 6-byte snap and 2-byte type
        data += sizeof(Rfc1042Hdr_t);
        pRxPD->RxPktOffset += sizeof(Rfc1042Hdr_t);
        pRxPD->RxPktLength -= sizeof(Rfc1042Hdr_t);
        convert_to_enetII = 1;
    }

    ethHdr = (EthII_Hdr_t *) (data - sizeof(*ethHdr));

    if (!convert_to_enetII) {
        /* [BUG# 7872] To be consistent, FW can just pass 802.3 format to
           driver/host for all rx data packets. It's up to driver/host
           decision to convert any format they want since 802.3 + LLC + SNAP
           already has enough information about the packet. */
        ethHdr->ethertype =
            ((pRxPD->RxPktLength & 0xff00) >> 8) | ((pRxPD->
                                                     RxPktLength & 0x00ff) <<
                                                    8);
    }
    // 
    // Construct 802.3 header,
    // 
    if (Header.FrmCtl & IEEE80211_FC_TODS)
        memcpy((void *) ethHdr->dest_addr, (void *) Header.Addr3, ETH_ALEN);
    else
        memcpy((void *) ethHdr->dest_addr, (void *) Header.Addr1, ETH_ALEN);

    if (Header.FrmCtl & IEEE80211_FC_FROMDS) {
        if (Header.FrmCtl & IEEE80211_FC_TODS)
            memcpy((void *) ethHdr->src_addr, (void *) Header.Addr4, ETH_ALEN);
        else
            memcpy((void *) ethHdr->src_addr, (void *) Header.Addr3, ETH_ALEN);
    } else
        memcpy((void *) ethHdr->src_addr, (void *) Header.Addr2, ETH_ALEN);

    pRxPD->RxPktLength += sizeof(*ethHdr);
    pRxPD->RxPktOffset -= sizeof(*ethHdr);
}

/** 
 *  @brief This function check seq num
 *
 *  
 *  @param orig_pn original pn buffer
 *  @param new_pn  new pn buffer
 *  @return    WLAN_STATUS_SUCCESS or WLAN_STATUS_FAILURE
 */
static int
wlan_rx_check_seqNum(u8 * orig_pn, u8 * new_pn)
{
    int i;
    if ((orig_pn == NULL) || (new_pn == NULL)) {
        PRINTM(ERROR, "PN buffer is NULL ! new_pn=%p orig_pn=%p\n", new_pn,
               orig_pn);
        return WLAN_STATUS_FAILURE;
    }

    DBG_HEXDUMP(DAT_D, "wlan_rx_check_seqNum orig_pn", orig_pn, 16);
    DBG_HEXDUMP(DAT_D, "wlan_rx_check_seqNum new_pn", new_pn, 16);
    for (i = 15; i >= 0; i--) {
        if (new_pn[i] == orig_pn[i])
            continue;
        if (new_pn[i] > orig_pn[i]) {
            memcpy(orig_pn, new_pn, 16);
            return WLAN_STATUS_SUCCESS;
        }
        return WLAN_STATUS_FAILURE;
    }

    return WLAN_STATUS_FAILURE;
}

/** 
 *  @brief This function prepare the wapi header
 *    
 *  @param wmmEnabled wmm enabled flag  
 *  @param Addr1   address 1 of 802.11 header
 *  @param Addr2   address 2 of 802.11 header
 *  @param Addr3   address 3 of 802.11 header
 *  @param pWlanHdr   A pointer to wlan_802_11_header
 *  @return 	      N/A
 */
static void
wlan_prepare_wapi_header(u8 wmmEnabled,
                         WLAN_802_11_MAC_ADDRESS Addr1,
                         WLAN_802_11_MAC_ADDRESS Addr2,
                         WLAN_802_11_MAC_ADDRESS Addr3,
                         wlan_802_11_header * pWlanHdr)
{

    /* compose WAPI header */
    pWlanHdr->FrmCtl = IEEE80211_TYPE_DATA | IEEE80211_FC_TODS;
    if (wmmEnabled)
        pWlanHdr->FrmCtl |= IEEE80211_SUBTYPE_QOS;
    pWlanHdr->DurationId = 0;

    // infra mode 
    // Address 1: RA = BSSID
    // Address 2: TA = SA
    // Address 3: RA = DA

    memcpy((PVOID) (pWlanHdr->Addr1), Addr1, sizeof(WLAN_802_11_MAC_ADDRESS));

    memcpy((PVOID) (pWlanHdr->Addr2), Addr2, sizeof(WLAN_802_11_MAC_ADDRESS));
    memcpy((PVOID) (pWlanHdr->Addr3), Addr3, sizeof(WLAN_802_11_MAC_ADDRESS));

    memset((PVOID) (pWlanHdr->Addr4), 0x00, sizeof(WLAN_802_11_MAC_ADDRESS));

    pWlanHdr->SeqCtl = 0;
}

/** 
 *  @brief This function increse the sequence num
 *    
 *  @param pn         pointer to pn buffer
 *  @param inc        increase num
 *  @param out        pointer to out buffer
 *  @return 	      N/A
 */
static void
wlan_tx_increase_seqNum(u32 * pn, u8 inc, u8 * out)
{
    int i;
    u32 temp = pn[0];

    PRINTM(INFO, "wlan_tx_increase_seqNum 1 = 0x%08x-%08x-%08x-%08x\n", pn[0],
           pn[1], pn[2], pn[3]);

    for (i = 0; i < 4; i++) {
        temp = pn[i];
        if ((temp + inc) > pn[i]) {
            pn[i] += inc;
            break;
        }
        pn[i] += inc;
        inc = 1;
    }
    for (i = 0; i < 4; i++)
        *(u32 *) & out[4 * i] = wlan_cpu_to_le32(pn[i]);

    PRINTM(INFO, "wlan_tx_increase_seqNum 2 = 0x%08x-%08x-%08x-%08x\n", pn[0],
           pn[1], pn[2], pn[3]);

    DBG_HEXDUMP(DAT_D, "wlan_tx_increase_seqNum 2", out, 16);
}

/********************************************************
		Global functions
********************************************************/
/** 
 *  @brief This function process rx wapi pkt
 *
 *  
 *  @param priv    A pointer to wlan_private
 *  @param skb     A pointer to skb which includes the received packet
 *  @param pRxPkt  A pointer to RxPacketHdr_t structure
 *  @param pRxPD   A pointer to RxPD structure
 *  @return        pkt_type
 */
int
wlan_process_rx_wapi_pkt(wlan_private * priv, struct sk_buff *skb,
                         RxPacketHdr_t * pRxPkt, RxPD * pRxPD)
{
    wlan_adapter *Adapter = priv->adapter;
    wapi_key *pKeyUsed = NULL;
    wlan_802_11_header *pWapiHdr = (wlan_802_11_header *) pRxPkt;
    wapi_header *pWapi = (wapi_header *) pRxPkt;
    u8 hdrLen;
    u16 seqNum = 0;
    u8 fragNum = 0;
    u8 moreFlag = 0;
    u8 retryFlag = 0;
    int pkt_type = PKT_DROP;
    struct sk_buff *new_skb = NULL;

    seqNum = pWapiHdr->SeqCtl >> 4;
    fragNum = pWapiHdr->SeqCtl & 0x000F;
    moreFlag = (pWapiHdr->FrmCtl & IEEE80211_MORE_FLAG) ? 1 : 0;
    retryFlag = (pWapiHdr->FrmCtl & IEEE80211_RETRY) ? 1 : 0;

    if (seqNum == Adapter->last_seq) {
        /* drop retry packet */
        if (retryFlag && (!moreFlag) && (!fragNum)) {
            PRINTM(DATA, "drop retry pkt\n");
            goto done;
        }
        /* Drop wrong frag pkt */
        if (fragNum && !Adapter->frag_skb) {
            PRINTM(ERROR,
                   "frag number wrong, fragnum=%d, last_frag=%d, frag_buf is NULL\n",
                   fragNum, Adapter->last_frag);
            goto done;
        }
        /* drop wrong frag pkt */
        if (fragNum && (fragNum != (Adapter->last_frag + 1))) {
            if (Adapter->frag_skb) {
                kfree_skb(Adapter->frag_skb);
                Adapter->frag_skb = NULL;
                Adapter->last_frag = 0;
            }
            PRINTM(ERROR, "frag number wrong, fragnum=%d, last_frag=%d\n",
                   fragNum, Adapter->last_frag);
            goto done;
        }
        /* drop retry frag start pkt */
        if (moreFlag && (fragNum == 0)) {
            PRINTM(DATA, "drop retry frag start pkt\n");
            goto done;
        }
        /* frag pkt and last frag pkt */
        if (moreFlag && fragNum)
            pkt_type = PKT_FRAG;
        else
            pkt_type = PKT_FRAG_LAST;
        Adapter->last_frag = fragNum;
    } else if (fragNum) {
        /* drop wrong frag pkt, we didn't receive the frag_start pkt */
        goto done;
    } else {
        /* frag start pkt and no frag pkt */
        if (moreFlag && (fragNum == 0))
            pkt_type = PKT_FRAG_START;
        else
            pkt_type = PKT_NO_FRAG;
        Adapter->last_seq = seqNum;
        Adapter->last_frag = fragNum;
    }

    if (pWapiHdr->FrmCtl & IEEE80211_FC_PROTECT) {
        if (pWapiHdr->Addr1[0] & 0x01)
            pKeyUsed = wapi_get_key(Adapter, pWapi->KeyIdx, 0);
        else
            pKeyUsed = wapi_get_key(Adapter, pWapi->KeyIdx, 1);
        hdrLen = sizeof(wapi_header);
        if (!pKeyUsed || !pKeyUsed->is_key_set) {
            pkt_type = PKT_DROP;
            PRINTM(ERROR, "Key is not ready, drop encrpted Rx Pkt\n");
            goto done;
        }
        if (!wapi_decrypt_rx_packet(pRxPD->Priority,
                                    (u8 *) pRxPkt,
                                    pRxPD->RxPktLength,
                                    &pKeyUsed->rk, &pKeyUsed->mic_rk)) {
            pkt_type = PKT_DROP;
            PRINTM(ERROR, "Fail to decrypt Rx Pkt\n");
            goto done;
        }
        pRxPD->RxPktLength -= MIC_SIZE;
        skb_trim(skb, skb->len - MIC_SIZE);
        // check PN fail (drop packet?)
        if (wlan_rx_check_seqNum(pKeyUsed->RxPN, pWapi->PN) ==
            WLAN_STATUS_FAILURE) {
            PRINTM(ERROR, "Check Rx PN data Fail\n");
        }
    } else
        hdrLen = sizeof(wlan_802_11_header);
    if (fragNum == 0) {
        wlan_genhdr_to_8023(hdrLen, (u8 *) pWapiHdr, pRxPD);
        if (pkt_type == PKT_FRAG_START) {
            if (Adapter->frag_skb)
                kfree_skb(Adapter->frag_skb);
            Adapter->frag_skb = skb;
        }
    } else {
        /* chop of header */
        if (pWapiHdr->FrmCtl & IEEE80211_FC_PROTECT)
            skb_pull(skb, pRxPD->RxPktOffset + sizeof(wapi_header));
        else
            skb_pull(skb, pRxPD->RxPktOffset + sizeof(wlan_802_11_header));
        if (skb_tailroom(Adapter->frag_skb) < skb->len) {
            new_skb =
                skb_copy_expand(Adapter->frag_skb,
                                skb_headroom(Adapter->frag_skb), skb->len,
                                GFP_ATOMIC);
            if (!new_skb) {
                PRINTM(ERROR, "fail to re_alloc skb\n");
                pkt_type = PKT_DROP;
                goto done;
            }
            kfree_skb(Adapter->frag_skb);
            Adapter->frag_skb = new_skb;
        }
        memcpy(Adapter->frag_skb->data + Adapter->frag_skb->len, skb->data,
               skb->len);
        skb_put(Adapter->frag_skb, skb->len);
    }
  done:
    return pkt_type;
}

/** 
 *  @brief This function retrieves the WAPI fragment size
 *    
 *  @param Adapter          Pointer to Adapter
 *  @param TxPktLength      Tx packet length
 *  @param FragCnt          Fragmentation count
 *  @param FragThreshold    Fragmentation threshold
 *  @param LastPktLen       Last packet length
 *  @return 	            N/A
 */
u16
wlan_get_wapi_fragment_size(wlan_adapter * Adapter, u16 TxPktLength,
                            u8 * FragCnt, u16 * FragThreshold, u16 * LastPktLen)
{
    u16 ExtraSize = 0;

    *FragCnt = 1;
    *FragThreshold = Adapter->FragThsd;
    *LastPktLen = 0;

    if (Adapter->FragThsd && (Adapter->FragThsd < MRVDRV_FRAG_MAX_VALUE)) {
        if (*FragThreshold < WAPI_FRAG_MIN_SIZE) {
            *FragThreshold = WAPI_FRAG_MIN_SIZE;
        }
        /* prepare frag threshold */
        *FragThreshold -=
            (IEEE80211_HEADER_SIZE + 2 + PN_SIZE + MIC_SIZE + FCS_SIZE);

        if (Adapter->wmm.enabled)
            *FragThreshold -= QOS_CTRL_SIZE;

        *FragThreshold -= (*FragThreshold & 0x3);

        // caculate and extend the buffer size needed
        *FragCnt = (TxPktLength / *FragThreshold);
        *LastPktLen = TxPktLength % *FragThreshold;

        if (*LastPktLen)
            (*FragCnt)++;

        if (*FragCnt > 1) {
            ExtraSize = (*FragCnt - 1) * (MIC_SIZE + sizeof(wapi_frag_hdr)) + 4;
        } else {
            *FragCnt = 1;
        }

    }
    return ExtraSize;
}

/** 
 *  @brief This function prepare the tx wapi packet
 *    
 *  @param Adapter          Pointer to Adapter
 *  @param pWapiHdr         Pointer to wapi_header structure
 *  @param pLocalTxPD       Pointer to TxPD structure
 *  @param skb              Pointer to skb structure
 *  @param DestAddr         Dest Addr
 *  @param insert8023Bytes  Insert 8023 bytes
 *  @param eth_type         Ethernet type
 *  @param FragCnt          Fragmentation count
 *  @param FragThreshold    Fragmentation threshold
 *  @param LastPktLen       Last packet length
 *  @return 	            N/A
 */
void
wlan_prepare_tx_wapi_pkt(wlan_adapter * Adapter, wapi_header * pWapiHdr,
                         TxPD * pLocalTxPD, struct sk_buff *skb, u8 * DestAddr,
                         u8 insert8023Bytes, u16 eth_type, u8 FragCnt,
                         u16 FragThreshold, u16 LastPktLen)
{
    wapi_key *pKeyUsed = NULL;
    wapi_frag_hdr *pFragInfo = NULL;
    char LLC[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
    u8 PN[MAX_FRAGMENT_NUM][PN_SIZE];
    u8 *pFragData[MAX_FRAGMENT_NUM];
    u8 *pData = NULL;
    u8 QosEnable = Adapter->wmm.enabled;
    u32 TxPktLength;
    int i;
    u16 WapiHdrLen = sizeof(wapi_header);
    u16 FragHdrLen = sizeof(wapi_frag_hdr);

    ENTER();

    if (insert8023Bytes) {
        memcpy((skb->data - insert8023Bytes), LLC, insert8023Bytes);
        pLocalTxPD->TxPktLength += insert8023Bytes;
    }

    wlan_prepare_wapi_header(QosEnable,
                             Adapter->CurBssParams.BSSDescriptor.MacAddress,
                             Adapter->CurrentAddr,
                             DestAddr, (wlan_802_11_header *) pWapiHdr);

    if (Adapter->SecInfo.WAPI_key_on && (eth_type != WAPI_PKT)) {
        pKeyUsed = &Adapter->cur_wapi_key.Wapi_uni_key;

        pWapiHdr->WlanHdr.FrmCtl |= IEEE80211_FC_PROTECT;
        pWapiHdr->KeyIdx = pKeyUsed->keyid;
        pWapiHdr->Reserved = 0;

        if (FragCnt == 1) {
            pLocalTxPD->TxPktLength += WapiHdrLen;
            wlan_tx_increase_seqNum(Adapter->cur_wapi_key.WAPI_TxPN, 2,
                                    (char *) &PN[0]);
            memcpy((PVOID) (pWapiHdr->PN), (char *) &PN[0],
                   sizeof(pWapiHdr->PN));
            wapi_encrypt_tx_packet(QosEnable, pLocalTxPD->Priority,
                                   (PUCHAR) pWapiHdr, pLocalTxPD->TxPktLength,
                                   &pKeyUsed->rk, &pKeyUsed->mic_rk);
            pLocalTxPD->TxPktLength += MIC_SIZE;
            skb->len += MIC_SIZE;
        } else {
            pLocalTxPD->TxPktLength +=
                ((MIC_SIZE + FragHdrLen) * FragCnt) + WapiHdrLen - PN_SIZE;

            pData = (u8 *) pWapiHdr + WapiHdrLen;
            /* (wapiHdr + 4bytes + PN + data + mic) + (4byte + PN + data + mic) 
               + ... */
            for (i = 0; i < FragCnt; i++) {
                if (i == 0) {
                    pFragData[i] = (u8 *) pWapiHdr + WapiHdrLen - PN_SIZE;
                } else {
                    pFragData[i] =
                        pFragData[i - 1] + FragHdrLen + FragThreshold +
                        MIC_SIZE;
                }
                wlan_tx_increase_seqNum(Adapter->cur_wapi_key.WAPI_TxPN, 2,
                                        (char *) &PN[i]);
            }

            for (i = (FragCnt - 1); i >= 0; i--) {
                /* mark fragment length */
                pFragInfo = (wapi_frag_hdr *) pFragData[i];

                if (i <= (FragCnt - 2)) {
                    pWapiHdr->WlanHdr.FrmCtl |= IEEE80211_MORE_FLAG;
                    TxPktLength = FragThreshold;
                } else {
                    pWapiHdr->WlanHdr.FrmCtl &= ~IEEE80211_MORE_FLAG;
                    TxPktLength = LastPktLen;
                }
                /* move data to destination */
                memmove((pFragData[i] + 4 + 16),
                        (pData + i * FragThreshold), TxPktLength);

                pWapiHdr->WlanHdr.SeqCtl = i;

                pFragInfo->FrmCtl = pWapiHdr->WlanHdr.FrmCtl;
                pFragInfo->FragPktLen = TxPktLength + MIC_SIZE + PN_SIZE;

                memmove((pFragInfo->PN), (char *) &PN[i], PN_SIZE);

                wapi_encrypt_frag_packet(QosEnable, pLocalTxPD->Priority, pWapiHdr, pFragData[i], TxPktLength,  // pure 
                                                                                                                // data 
                                                                                                                // length 
                                                                                                                // 
                                         &pKeyUsed->rk, &pKeyUsed->mic_rk);
            }
            skb->len = pLocalTxPD->TxPktLength - WapiHdrLen;

        }                       // fragment end
    } else
        pLocalTxPD->TxPktLength += sizeof(wlan_802_11_header);

    LEAVE();
}
