def table_lexical_projection(out):
    # No raw row, PID/UID value, state text, token, table hash or stderr is public.
    classes=('ascii_decimal','negative_decimal','positive_decimal','other_ascii','missing')
    columns=[{name:0 for name in classes} for _ in range(4)]
    failed_columns=[0,0,0,0]
    widths={str(n):0 for n in range(6)}
    widths['more_than_5']=0
    total=0;rejected=0;first_rejected=None
    for line in out.decode('ascii','strict').splitlines():
        remaining()
        total+=1
        need(total<=8192,'public_process_row_count_bound')
        fields=line.split();width=len(fields)
        widths[str(width) if width<=5 else 'more_than_5']+=1
        failed=[]
        for index in range(4):
            if index>=width:
                kind='missing'
            else:
                token=fields[index]
                if token.isdecimal():kind='ascii_decimal'
                elif token.startswith('-') and token[1:].isdecimal():kind='negative_decimal'
                elif token.startswith('+') and token[1:].isdecimal():kind='positive_decimal'
                else:kind='other_ascii'
            columns[index][kind]+=1
            if kind!='ascii_decimal':
                failed.append(index+1);failed_columns[index]+=1
        if width!=5 or failed:
            rejected+=1
            if first_rejected is None:
                first_rejected={'fieldCount':width,'failedNumericColumns':failed}
    return {'rowCount':total,'rowsRejectedByOriginalPredicate':rejected,
        'originalPredicateAllPassed':rejected==0,'fieldCountHistogram':widths,
        'numericColumnLexicalCounts':columns,'failedNumericColumnCounts':failed_columns,
        'firstRejectedShape':first_rejected,'rawRowsOrTokensOrHashExported':False}

