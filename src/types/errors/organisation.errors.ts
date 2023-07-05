export type CreateOrganisationErrors = 'NO_ORGANISATION_TITLE' |
	'NO_ORGANISATION_ADMIN_IDENTIFIER' |
	'DUPLICATE_TITLE' |
	'DB_ERROR';

export type GetOrganisationErrors = 'ORGANISATION_NOT_FOUND' | 'DB_ERROR';