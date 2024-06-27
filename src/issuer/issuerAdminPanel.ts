import { Router } from "express";
import locale from "../configuration/locale";
import { CredentialStatusList } from '../lib/CredentialStatus';

const issuerAdminPanel = Router();

async function fetchCredentialStatusList() {
    try {
        const data = await CredentialStatusList.get();
        console.log('Credential Status List:', data);

        return data;
    } catch (error) {
        console.error('Error fetching credential status list:', error);
        return [];
    }
}

issuerAdminPanel.get('/', async (req, res) => {
    const data = await fetchCredentialStatusList();

    return res.render('issuer/admin.pug', {
        title: 'Admin Panel',
        lang: req.lang,
        locale: locale[req.lang],
        credentialStatusList: data
    });
});

issuerAdminPanel.post('/revoke', async (req, res) => {
  try {
    const { credential_id } = req.body;
    console.log('Credential ID to revoke:', credential_id);
    await CredentialStatusList.revoke(credential_id);
    res.status(200).send({ message: 'Credential revoked successfully' });
  } catch (error) {
    console.error('Error revoking credential:', error);
    res.status(500).send({ error: 'Failed to revoke credential' });
  }
});

export default issuerAdminPanel;
