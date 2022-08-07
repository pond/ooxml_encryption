References:

    https://www.npmjs.com/package/secure-spreadsheet
    https://www.npmjs.com/package/xlsx-populate

Generation of "node_encrypted_spreadsheet.xlsx" required changes to code above.
When given an Excel file as input, `secure-spreadsheet` was running it through
its Excel processor anyway, regenerating it into a new file and encrypting
different data than given on `stdin` as a result. Bypassing this and passing
the file data to the encryptor directly resulted in the output seen here. The
same result could be generated from the Node REPL, but I preferred to use as
much of the surrounding code path as possible for validation of results.
