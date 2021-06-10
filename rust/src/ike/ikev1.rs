/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// Author: Frank Honza <frank.honza@dcso.de>

use crate::applayer::*;
use crate::common::to_hex;
use crate::core::STREAM_TOSERVER;
use crate::ike::ike::{IKEState, IkeEvent};
use crate::ike::parser::*;
use nom;
use std;
use std::collections::HashSet;

#[derive(Default)]
pub struct IkeV1Header {
    pub exchange_type: Option<u8>,
    pub encrypted_payloads: bool,

    pub key_exchange: Vec<u8>,
    pub nonce: Vec<u8>,
    pub vendor_ids: Vec<String>,
}

#[derive(Default)]
pub struct Ikev1ParticipantData {
    pub key_exchange: String,
    pub nonce: String,
    pub vendor_ids: HashSet<String>,
    /// nested Vec, outer Vec per Proposal/Transform, inner Vec has the list of attributes.
    pub transforms: Vec<Vec<SaAttribute>>,
}

impl Ikev1ParticipantData {
    pub fn reset(&mut self) {
        self.key_exchange.clear();
        self.nonce.clear();
        self.vendor_ids.clear();
        self.transforms.clear();
    }

    pub fn update(
        &mut self, key_exchange: &String, nonce: &String, vendor_ids: &Vec<String>,
        transforms: &Vec<Vec<SaAttribute>>,
    ) {
        self.key_exchange = key_exchange.clone();
        self.nonce = nonce.clone();
        self.vendor_ids.extend(vendor_ids.iter().cloned());
        self.transforms.extend(transforms.iter().cloned());
    }
}

#[derive(Default)]
pub struct Ikev1Container {
    pub domain_of_interpretation: Option<u32>,
    pub client: Ikev1ParticipantData,
    pub server: Ikev1ParticipantData,
}

pub fn handle_ikev1(
    state: &mut IKEState, current: &[u8], isakmp_header: IsakmpHeader, direction: u8,
) -> AppLayerResult {
    let mut tx = state.new_tx();

    tx.ike_version = 1;
    tx.hdr.spi_initiator = format!("{:016x}", isakmp_header.init_spi);
    tx.hdr.spi_responder = format!("{:016x}", isakmp_header.resp_spi);
    tx.hdr.maj_ver = isakmp_header.maj_ver;
    tx.hdr.min_ver = isakmp_header.min_ver;
    tx.hdr.ikev1_header.exchange_type = Some(isakmp_header.exch_type);
    tx.hdr.msg_id = isakmp_header.msg_id;
    tx.hdr.flags = isakmp_header.flags;

    let mut cur_payload_type = isakmp_header.next_payload;
    let mut payload_types: HashSet<u8> = HashSet::new();
    payload_types.insert(cur_payload_type);

    if isakmp_header.flags & 0x01 != 0x01 {
        match parse_ikev1_payload_list(current) {
            Ok((rem, payload_list)) => {
                for isakmp_payload in payload_list {
                    if let Err(_) = parse_payload(
                        cur_payload_type,
                        isakmp_payload.data,
                        isakmp_payload.data.len() as u16,
                        &mut state.ikev1_container.domain_of_interpretation,
                        &mut tx.hdr.ikev1_header.key_exchange,
                        &mut tx.hdr.ikev1_header.nonce,
                        &mut tx.hdr.ikev1_transforms,
                        &mut tx.hdr.ikev1_header.vendor_ids,
                        &mut payload_types,
                    ) {
                        SCLogDebug!("Error while parsing IKEV1 payloads");
                        return AppLayerResult::err();
                    }

                    cur_payload_type = isakmp_payload.payload_header.next_payload;
                }

                if payload_types.contains(&(IsakmpPayloadType::SecurityAssociation as u8)) {
                    // clear transforms on a new SA in case there is happening a new key exchange
                    // on the same flow, elsewise properties would be added to the old/other SA
                    if direction == STREAM_TOSERVER {
                        state.ikev1_container.client.reset();
                    } else {
                        state.ikev1_container.server.reset();
                    }
                }

                // add transaction values to state values
                if direction == STREAM_TOSERVER {
                    state.ikev1_container.client.update(
                        &to_hex(tx.hdr.ikev1_header.key_exchange.as_ref()),
                        &to_hex(tx.hdr.ikev1_header.nonce.as_ref()),
                        &tx.hdr.ikev1_header.vendor_ids,
                        &tx.hdr.ikev1_transforms,
                    );
                } else {
                    if state.ikev1_container.server.transforms.len() <= 1
                        && state.ikev1_container.server.transforms.len()
                            + tx.hdr.ikev1_transforms.len()
                            > 1
                    {
                        SCLogDebug!("More than one chosen server proposal");
                        state.set_event(IkeEvent::MultipleServerProposal);
                    }

                    state.ikev1_container.server.update(
                        &to_hex(tx.hdr.ikev1_header.key_exchange.as_ref()),
                        &to_hex(tx.hdr.ikev1_header.nonce.as_ref()),
                        &tx.hdr.ikev1_header.vendor_ids,
                        &tx.hdr.ikev1_transforms,
                    );
                }

                if rem.len() > 0 {
                    // more data left unread than should be
                    SCLogDebug!("Unread Payload Data");
                    state.set_event(IkeEvent::PayloadExtraData);
                }
            }
            Err(nom::Err::Incomplete(_)) => {
                SCLogDebug!("Insufficient data while parsing IKEV1");
                return AppLayerResult::err();
            }
            Err(_) => {
                SCLogDebug!("Error while parsing payloads and adding to the state");
                return AppLayerResult::err();
            }
        }
    }

    tx.payload_types.ikev1_payload_types = Some(payload_types);
    tx.hdr.ikev1_header.encrypted_payloads = isakmp_header.flags & 0x01 == 0x01;
    state.transactions.push(tx);
    return AppLayerResult::ok();
}
