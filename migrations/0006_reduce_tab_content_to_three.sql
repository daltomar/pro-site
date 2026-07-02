DELETE FROM tab_content WHERE tab_number = 4;

ALTER TABLE tab_content DROP CONSTRAINT tab_content_tab_number_check;
ALTER TABLE tab_content ADD CONSTRAINT tab_content_tab_number_check CHECK (tab_number BETWEEN 1 AND 3);
