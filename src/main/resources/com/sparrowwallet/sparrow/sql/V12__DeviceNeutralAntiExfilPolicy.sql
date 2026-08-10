alter table keystore add column antiExfilPolicy integer after antiExfilRequired;
update keystore set antiExfilPolicy = case
    when antiExfilRequired then 2
    when walletModel = 18 then 1
    else 0
end;
alter table keystore alter column antiExfilPolicy set not null;
