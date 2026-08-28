alter table keystore add column antiExfilProfile varchar after antiExfilPolicy;
-- WalletModel ordinal 18 is SEEDSIGNER (pinned by Drongo KeystoreTest)
update keystore set antiExfilProfile = case
    when walletModel = 18 and antiExfilPolicy <> 0 then 'aext-v1'
    else 'none'
end;
alter table keystore alter column antiExfilProfile set not null;
