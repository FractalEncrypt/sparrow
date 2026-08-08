alter table keystore add column antiExfilRequired boolean after deviceRegistration;
update keystore set antiExfilRequired = false where antiExfilRequired is null;
alter table keystore alter column antiExfilRequired set not null;
