use dash_spv_masternode_processor::{crypto::byte_util::Reversable, tx::Transaction};

use crate::coinjoin::CoinJoin;

#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum CoinJoinTransactionType {
    None,
    CreateDenomination,
    MakeCollateralInputs,
    MixingFee,
    Mixing,
    Send,
}

impl CoinJoinTransactionType {
    pub fn from_tx(tx: &Transaction, input_values: &Vec<u64>) -> Self {
        let input_sum: u64 = input_values.iter().sum();

        if tx.inputs.len() == tx.outputs.len() && tx.outputs.iter().all(|output| CoinJoin::is_denominated_amount(output.amount)) {
            return Self::Mixing;
        } else if Self::is_mixing_fee(tx, input_sum) {
            return Self::MixingFee;
        } else {
            let mut make_collateral = false;
            if tx.outputs.len() == 2 {
                let amount_0 = tx.outputs[0].amount;
                let amount_1 = tx.outputs[1].amount;
                // <case1>, see CCoinJoinClientSession.makeCollateralAmounts
                make_collateral = (amount_0 == CoinJoin::get_max_collateral_amount() && !CoinJoin::is_denominated_amount(amount_1) && amount_1 >= CoinJoin::get_collateral_amount()) ||
                    (amount_1 == CoinJoin::get_max_collateral_amount() && !CoinJoin::is_denominated_amount(amount_0) && amount_0 >= CoinJoin::get_collateral_amount()) ||
                    // <case2>, see CCoinJoinClientSession.makeCollateralAmounts
                    (amount_0 == amount_1 && CoinJoin::is_collateral_amount(amount_0));
            } else if tx.outputs.len() == 1 {
                // <case3>, see CCoinJoinClientSession.makeCollateralAmounts
                make_collateral = CoinJoin::is_collateral_amount(tx.outputs[0].amount);
            }
            if make_collateral {
                return Self::MakeCollateralInputs;
            } else {
                for output in &tx.outputs {
                    if CoinJoin::is_denominated_amount(output.amount) {
                        return Self::CreateDenomination; // Done, it's definitely a tx creating mixing denoms, no need to look any further
                    }
                }
            }
        }

        // is this a coinjoin send transaction
        if CoinJoinTransactionType::is_coinjoin_send(tx, &input_values) {
            return Self::Send;
        }

        return Self::None;
    }

    fn is_coinjoin_send(tx: &Transaction, input_values: &Vec<u64>) -> bool {
        let inputs_are_denominated = input_values.iter().all(|input| CoinJoin::is_denominated_amount(*input));
        let fee = CoinJoinTransactionType::get_fee(tx, input_values);
        
        return inputs_are_denominated && fee.map_or(false, |f| f != 0);
    }

    fn is_mixing_fee(tx: &Transaction, inputs_value: u64) -> bool {
        let outputs_value = tx.outputs.iter().map(|output| output.amount).sum();
        
        if inputs_value < outputs_value {
            return false;
        }

        let net_value = inputs_value - outputs_value;
        
        // check for the tx with OP_RETURN
        if outputs_value == 0 && tx.inputs.len() == 1 && tx.outputs.len() == 1 && tx.outputs[0].is_op_return() {
            return true;
        }

        return tx.inputs.len() == 1 && tx.outputs.len() == 1
            && CoinJoin::is_collateral_amount(inputs_value)
            && CoinJoin::is_collateral_amount(outputs_value)
            && CoinJoin::is_collateral_amount(net_value);
    }

    fn get_fee(tx: &Transaction, inputs_values: &Vec<u64>) -> Option<u64> {
        let mut fee: u64 = 0;

        if inputs_values.is_empty() || tx.outputs.is_empty() {
            return None;
        }

        for input_value in inputs_values {
            fee = fee.saturating_add(*input_value);
        }

        for output in &tx.outputs {
            fee = fee.saturating_sub(output.amount);
        }

        return Some(fee);
    }   
}
