#include "acctexchange.hpp"

void acctexchange::listforsale(account_name acct, extended_asset price, account_name recipient)
{
    require_auth(acct);

    eosio_assert(price.is_valid(), "Invalid price symbol");
    eosio_assert(is_account(price.contract), "Token contract does not exist");
    eosio_assert(price.amount > 0, "Price must be positive");

    eosio_assert(is_account(recipient), "Recipient does not exist");
    eosio_assert(acct != recipient, "Set a different recipient account");

    /*
     * This is to check whether acctexchange@eosio.code can pass acct@owner.
     * However, it's possible that after calling listforsale, the permission is removed.
     * In that case, any attempt to buy this account would fail. The admin shall forcibly remove
     * the listing by calling removesale.
     */
    action(permission_level(acct, N(owner)), _self, N(assertowner), assertowner_args{acct}).send();

    auto existingAcctPost = forsales.find(acct);
    eosio_assert(existingAcctPost == forsales.end(), "Account is already for sale");

    forsales.emplace(acct, [&](forsale &newSale) {
        newSale.acct = acct;
        newSale.price = price;
        newSale.recipient = recipient;
    });
}

void acctexchange::delistacct(account_name acct)
{
    require_auth(acct);

    auto existingAcctPost = forsales.find(acct);
    eosio_assert(existingAcctPost != forsales.end(), "Account is not for sale");

    forsales.erase(existingAcctPost);
}

void acctexchange::buyacct(account_name buyer, account_name target, extended_asset price, string pub_key)
{
    // Auth

    require_auth(buyer);

    auto existingAcctPost = forsales.find(target);
    eosio_assert(existingAcctPost != forsales.end(), "Account is not for sale");

    // Protection from price-change attack

    eosio_assert(existingAcctPost->price.get_extended_symbol() == price.get_extended_symbol(), "Wrong price symbol");
    eosio_assert(existingAcctPost->price.amount <= price.amount, "Provided price is too low");

    // Adjusts balance

    sub_balance(buyer, existingAcctPost->price);

    // Decodes public key

    eosio_assert(pub_key[0] == 'E' && pub_key[1] == 'O' && pub_key[2] == 'S', "Public key must start with EOS");

    string pub_key_str_raw = pub_key.substr(3);

    vector<unsigned char> pub_key_decoded;
    eosio_assert(decode_base58(pub_key_str_raw, pub_key_decoded), "Failed to decode public key");
    eosio_assert(pub_key_decoded.size() == 37, "Invalid public key");

    array<unsigned char, 33> pub_key_payload;
    copy_n(pub_key_decoded.begin(), 33, pub_key_payload.begin());

    // Reads fee settings

    // Transfers fee to ADMIN

    // Transfers price to recipient

    action(permission_level(_self, N(active)), existingAcctPost->price.contract, N(transfer), transfer_args{_self, existingAcctPost->recipient, asset(existingAcctPost->price.amount, existingAcctPost->price.symbol), "Your account has been successfully sold!"}).send();

    // Updates account owner permission

    vector<key_weight> owner_keys;
    owner_keys.push_back({public_key_data{0, pub_key_payload}, 1});
    updateauth_args owner{
        target, N(owner), 0,
        authority{1, 0, owner_keys, vector<permission_level_weight>()}};

    action(permission_level(target, N(owner)), N(eosio), N(updateauth), owner).send();

    // Updates account active permission

    vector<key_weight> active_keys;
    active_keys.push_back({public_key_data{0, pub_key_payload}, 1});
    updateauth_args active{
        target, N(active), N(owner),
        authority{1, 0, active_keys, vector<permission_level_weight>()}};

    action(permission_level(target, N(owner)), N(eosio), N(updateauth), active).send();

    // Erases sale post from DB

    forsales.erase(existingAcctPost);
}

void acctexchange::withdraw(account_name user, extended_asset quantity)
{
    require_auth(user);

    eosio_assert(quantity.amount > 0, "Must withdraw positive amount");

    sub_balance(user, quantity);

    action(permission_level(_self, N(active)), quantity.contract, N(transfer), transfer_args{_self, user, asset(quantity.amount, quantity.symbol), "Withdrawal"}).send();
}

void acctexchange::adjustfee(uint64_t new_fee)
{
    require_auth(ADMIN);
}

void acctexchange::removesale(account_name acct)
{
    require_auth(ADMIN);

    auto existingAcctPost = forsales.find(acct);
    eosio_assert(existingAcctPost != forsales.end(), "Account is not for sale");

    forsales.erase(existingAcctPost);
}

void acctexchange::assertowner(account_name acct)
{
    require_auth2(acct, N(owner));
}

void acctexchange::handle_transfer(account_name from, account_name to, extended_asset quantity, string memo)
{
    // Ignores the message if it's not a transfer of CORE to this contract

    if (quantity.contract != N(eosio.token) || quantity.symbol != CORE_SYMBOL)
        return;
    if (from == _self || to != _self)
        return;

    eosio_assert(quantity.is_valid(), "Invalid deposit token symbol");
    eosio_assert(quantity.amount > 0, "Must transfer positive amount");

    tbl_user_balances user_balances(_self, from);
    auto existingBalance = user_balances.find(from);

    if (existingBalance == user_balances.end())
        user_balances.emplace(_self, [&](user_balance &newBalance) {
            newBalance.user = from;
            newBalance.balances.push_back(quantity);
        });
    else
    {
        auto balanceItem = existingBalance->balances.begin();
        for (; balanceItem != existingBalance->balances.end(); existingBalance++)
            if (balanceItem->get_extended_symbol() == quantity.get_extended_symbol())
                break;

        bool itemExists = balanceItem != existingBalance->balances.end();

        if (itemExists)
        {
            eosio_assert(balanceItem->amount + quantity.amount > quantity.amount, "Balance overflow");
            user_balances.modify(existingBalance, _self, [&](user_balance &userBalance) {
                for (auto it = userBalance.balances.begin(); it != userBalance.balances.end(); it++)
                    if (it->get_extended_symbol() == quantity.get_extended_symbol())
                    {
                        (*it) += quantity;
                        break;
                    }
            });
        }
        else
        {
            user_balances.modify(existingBalance, _self, [&](user_balance &userBalance) {
                userBalance.balances.push_back(quantity);
            });
        }
    }
}

void acctexchange::sub_balance(account_name user, extended_asset quantity)
{
    tbl_user_balances user_balances(_self, user);
    auto existingBalance = user_balances.find(user);
    eosio_assert(existingBalance != user_balances.end(), "Balance object not found");

    auto balanceItem = existingBalance->balances.begin();
    for (; balanceItem != existingBalance->balances.end(); existingBalance++)
        if (balanceItem->get_extended_symbol() == quantity.get_extended_symbol())
            break;

    eosio_assert(balanceItem != existingBalance->balances.end(), "Balance item not found");
    eosio_assert(balanceItem->amount >= quantity.amount, "Insufficient balance");

    bool erase_item = balanceItem->amount == quantity.amount;

    if (erase_item && existingBalance->balances.size() == 1)
        user_balances.erase(existingBalance);
    else
        user_balances.modify(existingBalance, user, [&](user_balance &userBalance) {
            for (auto it = userBalance.balances.begin(); it != userBalance.balances.end(); it++)
                if (it->get_extended_symbol() == quantity.get_extended_symbol())
                {
                    if (erase_item)
                        userBalance.balances.erase(it);
                    else
                        (*it) -= quantity;
                    break;
                }
        });
}