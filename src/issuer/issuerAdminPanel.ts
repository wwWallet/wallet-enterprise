import { Router } from "express";
import locale from "../configuration/locale";
import { CredentialStatusList } from '../lib/CredentialStatus';
import config from "../../config";

const issuerAdminPanel = Router();

async function fetchCredentialStatusList(codeName: string) {
    try {
        const data = await CredentialStatusList.get();
        console.log('Credential Status List:', data);

        const filteredData = data.crl.filter(item => item.issuer_name === codeName);

        return filteredData;
    } catch (error) {
        console.error('Error fetching credential status list:', error);
        return [];
    }
}

issuerAdminPanel.get('/', async (req, res) => {

    const filteredData = await fetchCredentialStatusList(config.codeName);

    return res.render('issuer/admin.pug', {
        title: 'Admin Panel',
        lang: req.lang,
        locale: locale[req.lang],
        credentialStatusList: filteredData
    });
});

export default issuerAdminPanel;
