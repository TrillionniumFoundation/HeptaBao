import copy
import unittest
import pki_issuer_alias_strict_live as probe


def projection(case, suffix, negative=False):
    row = {'case':case, 'status':500 if negative else 200,
        'provider_sign_entries':0,'audit_request_delta':1,'audit_response_delta':1,
        'passed':True,'content_type':'application/json' if negative else probe.MEDIA[suffix],
        'private_fields_absent':True}
    if negative:
        row.update(data_fields=[],no_material=True,not_default_material=True)
        return row
    row.update(public_material_valid=True,exact_original_der=True,
        pem_final_lf_count=None if suffix=='der' or suffix.endswith('/der') else 1)
    if suffix=='json':
        row.update(data_fields=['ca_chain','certificate','issuer_id','issuer_name'],
            data_field_types={'ca_chain':'list','certificate':'str','issuer_id':'str','issuer_name':'str'},
            issuer_id_exact=True,issuer_name_exact=True,chain_exact_original_certificate=True)
    elif suffix in ('crl','crl/delta'):
        row.update(data_fields=['crl'],data_field_types={'crl':'str'})
    return row


def complete():
    rows=[]
    for case in probe.EXPECTED:
        if case.startswith(('public.','restart.','unknown.')):
            suffix=case.split('.',3)[3] if case.startswith('public.') else case.split('.',2)[2]
            rows.append(projection(case,suffix,case.startswith('unknown.')))
        elif case in ('full_cache','delta_cache'):
            rows.append(projection(case,'crl/der'))
        else:rows.append({'case':case,'passed':True})
    indexed={r['case']:r for r in rows}
    statuses={'provider_health':200,'consumer_health':200,'provider_mount':204,
        'provider_key':200,'provider_public':200,'configuration':204,'mapping':204,
        'mount':204,'grant':204,'root':200,'restart_health':200}
    for case,status in statuses.items():indexed[case]['status']=status
    indexed['root']['provider_sign_entries']=3
    indexed['root_binding'].update(public_key_bound=True,private_fields_absent=True,root_sign_entries=3)
    indexed['owned_cleanup']['all_owned_stopped']=True
    return rows


class IssuerStrictContracts(unittest.TestCase):
    def test_all_115_cases_and_order_are_required(self):
        rows=complete();self.assertEqual(len(rows),115)
        self.assertTrue(probe.observation_contract_complete(rows))
        for bad in (rows[:-1],rows+[rows[0]],[None]+rows[1:]):
            self.assertFalse(probe.observation_contract_complete(bad))
        bad=rows.copy();bad[0],bad[1]=bad[1],bad[0]
        self.assertFalse(probe.observation_contract_complete(bad))

    def test_unknown_requires_actual_500_and_no_default_material(self):
        body={'errors':['synthetic unknown issuer']}
        self.assertTrue(probe.safe_unknown_response(500,'application/json',body,0))
        for status in (200,400,403,404,501,True):
            self.assertFalse(probe.safe_unknown_response(status,'application/json',body,0))
        for extra in ({'data':{}},{'certificate':'synthetic'},{'nested':[{'crl':None}]},
                      {'nested':{'private_key':None}},{'nested':{'external_key_ref':None}}):
            self.assertFalse(probe.safe_unknown_response(500,'application/json',{**body,**extra},0))
        row=projection('unknown.name.pem','pem',True)
        for key,value in (('no_material',False),('not_default_material',False),('private_fields_absent',False),('data_fields',['certificate'])):
            bad={**row,key:value};self.assertFalse(probe.exact_projection(bad,'pem',True))

    def test_selected_mime_and_one_final_lf_are_exact(self):
        for suffix in probe.ROUTES:
            row=projection('synthetic',suffix)
            self.assertTrue(probe.exact_projection(row,suffix))
            self.assertFalse(probe.exact_projection({**row,'content_type':'application/octet-stream'},suffix))
            for count in (0,2):
                self.assertFalse(probe.exact_projection({**row,'pem_final_lf_count':count},suffix))
        self.assertFalse(probe.exact_projection(projection('synthetic','der'),'ca_chain'))

    def test_closed_json_public_metadata_is_actually_bound(self):
        row=projection('synthetic','json')
        for key in ('issuer_id_exact','issuer_name_exact','chain_exact_original_certificate'):
            self.assertFalse(probe.exact_projection({**row,key:False},'json'))
        self.assertFalse(probe.exact_projection({**row,'data_fields':row['data_fields']+['external_key_ref']},'json'))
        self.assertFalse(probe.exact_projection({**row,'data_field_types':{**row['data_field_types'],'ca_chain':'str'}},'json'))
        row=projection('synthetic','crl')
        self.assertFalse(probe.exact_projection({**row,'data_fields':['crl','certificate']},'crl'))

    def test_signed_cache_and_original_der_cannot_be_static_ack(self):
        for key in ('public_material_valid','exact_original_der','private_fields_absent'):
            row=projection('synthetic','crl/delta/der')
            self.assertFalse(probe.exact_projection({**row,key:False},'crl/delta/der'))
        rows=complete();indexed={r['case']:r for r in rows}
        indexed['full_cache']['public_material_valid']=False
        self.assertFalse(probe.observation_contract_complete(rows))

    def test_zero_sign_and_one_request_response_audit_are_typed(self):
        row=projection('synthetic','pem')
        for key in ('provider_sign_entries','audit_request_delta','audit_response_delta'):
            for value in (False,True,-1,2):
                self.assertFalse(probe.exact_projection({**row,key:value},'pem'))
        self.assertFalse(probe.safe_unknown_response(500,'application/json',{'errors':['synthetic']},False))

    def test_original_root_needs_three_real_bound_provider_signatures(self):
        for key,value in (('public_key_bound',False),('private_fields_absent',False),('root_sign_entries',False),('root_sign_entries',0),('root_sign_entries',1)):
            rows=complete();indexed={r['case']:r for r in rows};indexed['root_binding'][key]=value
            self.assertFalse(probe.observation_contract_complete(rows))
        rows=complete();next(r for r in rows if r['case']=='root')['provider_sign_entries']=True
        self.assertFalse(probe.observation_contract_complete(rows))

    def test_cleanup_and_restart_are_required_with_true_boolean(self):
        for value in (False,1,None):
            rows=complete();rows[-1]['all_owned_stopped']=value
            self.assertFalse(probe.observation_contract_complete(rows))
        rows=complete();next(r for r in rows if r['case']=='restart.id.crl/delta/pem')['exact_original_der']=False
        self.assertFalse(probe.observation_contract_complete(rows))
        rows=complete();rows[0]['passed']=1
        self.assertFalse(probe.observation_contract_complete(rows))


if __name__=='__main__':unittest.main()
