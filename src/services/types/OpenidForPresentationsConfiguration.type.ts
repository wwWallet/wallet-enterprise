export type OpenidForPresentationsConfiguration = {
	baseUrl: string;
	client_id: string;
	redirect_uri: string;
	responseTypeSetting: "vp_token" | "id_token";
	authorizationServerWalletIdentifier: string;	
}