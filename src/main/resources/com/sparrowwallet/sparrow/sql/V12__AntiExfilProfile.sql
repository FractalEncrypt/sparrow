alter table keystore add column antiExfilProfile varchar after antiExfilPolicy;
update keystore set antiExfilProfile = case
    when walletModel = 18 and antiExfilPolicy <> 0 then 'AEXT_V1'
    else 'NONE'
end;
alter table keystore alter column antiExfilProfile set not null;
