const locale = {
	en: {
		Header: {
			issuer:"Diplomas Issuer",
			verifier: "Diplomas Verifier",
			title: "eDiplomas"
		},
		Footer: {
			services: "Services",
			documentation: "Documentation",
			adminLogin: "Verifier Panel",
			information: "Information",
			participatingInst: "Participating Institutions",
			termsOfUse: "Terms of Use",
			contact: "Contact",
			web: "Web",
			emailForOrgs: "E-mail for Institutions"
		},
		Index: {
			header: "Greek Universities Issuer Portal",
			description1: "Ediplomas is a Trusted Issuer that issues Greek HEI degrees in Verifiable Credential form. Through the new online eDiplomas platform, the citizen and owner of degrees issued by greek HEIs is able, by using their TAXISNet account.",
			description2: "The platform uses technologies which ensure the protection of private data as well as the authenticity of the degrees' information. By making the submission and degree verification processes simple and fast for the owner as well as the client, it is, at the same time, attempted to eliminate the phenomenon of fake and counterfeit degrees.",
			description3: "This is an eDiploma implementation for demo purposes only. It has been developed in the framework of EBSI Early Adopters Program and the Multi University Pilot, with the endorsement of the Greek Ministry of Education.",
			proceedButtonText: "Proceed",
			leftSideDesc: "I am a university graduate",
			rightSideDesc: "I am a university representative",
		},
		Holder: {
			actions: "Holder Actions",
			issue: {
				title: "Issue",
				desc: "I want to receive a diploma credential",
				studentIdDesc: "I want to receive a Student ID"
			},
			verify: {
				title: "Verify",
				desc: "I want to present a diploma credential",
			},
		},
		FlowSelection: {
			header: "Select Flow",
			description1: "On this step, you have to choose one of the following flows.",
			crossDeviceDescription: "Choose this option if you have a wallet on your mobile.",
			sameDeviceDescription: "Choose this option if you have a wallet application on this device",
		},
		CredentialSelection: {
			InstitutionSelection: {
				header: "Institution Selection",
				description1: "Choose your institution where you have credentials to receive",
				placeholder1: "Enter an institution name",
				continue: "Continue with credential selection",
				warning1: "Please select an institution"
			}
		},
		Login: {
			title: "Login",
			description1: "",
			taxis: "National Identifier Login",
			local: "Login",
			Error: {
				emptyUsername: "Please enter your username",
				emptyPassword: "Please enter your password",
				invalidCredentials: "Credentials do not match",
				networkError: "Network Error"
			}
		},
		Organisation: {
			Back: {
				verificationSubject: 'Verification Subject',
				organisation: 'Organisation',
				organisations: 'Organisations'
			},
			Organisations: {
				title: 'Organisations',
				createNew: 'Create new Organisation',
				searchByTitle: 'Search by Title',
				searchDesc: 'Filtering results for',
				searchClear: 'Clear search results',
				id: 'ID',
				titleCol: 'Title',
				representative: 'Representative',
			},
			CreateOrganisation: {
				header: 'Create Organisation',
				title: 'Title',
				invalidTitle: 'Please enter the Organisation name',
				duplicateTitle: 'Given Organisation name already exists',
				description: 'Description',
				identifier: 'Identifier',
				invalidIdentifier: 'Please enter the Identifier of the Organisation Administrator',
				details: 'Contact Details',
				fullname: 'Fullname',
				email: 'Email',
				phone: 'Phone',
				create: 'Create organisation',
				back: 'Back'
			},
			CreateSubject: {
				header: 'Create Subject',
				definition: {
					stepTitle: 'Presentation Definition',
					header: 'Presentation Definition',
					description: 'Choose a Presentation Definition',
					create: 'Create new Presentation Definition'
				},
				details: {
					stepTitle: 'Details',
					header: 'Subject Details',
					title: 'Title',
					feedback: 'Please enter a Subject Title',
					description: 'Description'
				},
				properties: {
					stepTitle: 'Properties',
					header: 'Subject Properties',
					visibility: 'Visibility',
					public: 'Visible (Public)',
					private: 'Hidden (Private)'
				},
				back: 'Back',
				next: 'Next',
				submit: 'Create'
			},
			CreateDefinition: {
				header: 'Create Presentation Definition',
				title: 'Title',
				type: 'Select a credential Type',
				schema: 'Select a JSON Schema',
				create: 'Create Presentation Definition',
				warning1: 'No credential type was selected',
				back: 'Back'
			},
			Organisation: {
				updateAlert: 'Contact details updated successfully',
				title: 'Organisation',
				details: {
					header: 'Contact Details',
					name: 'Representative name',
					phone: 'Phone number',
					email: 'Email address',
					update: 'Update Contact Details',
					error: {
						name: "Please enter the representative's name",
						phone: 'Please enter a valid phone number',
						email: 'Please enter a valid email address'
					}
				},
				subjects: 'Subjects',
				addSubject: 'Add Subject',
				subject: {
					definition: 'Expand Presentation Definition',
					expDate: 'Expires in',
					noExpDate: 'No Expiration Date',
					visibility: 'Visibility:',
					public: 'Public',
					private: 'Private',
					definitionTitle: 'Presentation Definition'
				}
			},
			Subject: {
				updateAlert: 'Subject details changed successfully',
				title: 'Verification Subject',
				details: {
					header: 'Verification Subject Details',
					titleError: 'Please enter a valid Verification Subject Title',
					expandDef: 'Expand Presentation Definition',
					visibility: 'Visibility',
					visible: 'Visible (Public)',
					hidden: 'Hidden (Private)',
					expiration: 'Expiration',
					never: 'Never',
					expirationError: 'Please enter a valid expiration date',
					expireNow: 'Expire Now',
					update: 'Update Verification Subject'
				},
				presentationDefinition: 'Presentation Definition',
				receivedPresentation: 'Received Presentations',
				showValid: 'Show Valid Presentations',
				showInvalid: 'Show Invalid Presentations',
				showingValid: 'Showing Valid Presentations',
				showingInvalid: 'Showing Invalid Presentations',
				id: 'ID',
				subject: 'Subject',
				date: 'Date'
			},
			VerifiablePresentation: {
				title: 'Verifiable Presentation',
				copyMessage: 'Copy Raw Presentation Content to Clipboard',
				copyAlertSuccess: 'Verifiable Presentation successfully copied to clipboard',
				copyAlertFail: 'Error copying Verifiable Presentation',
				includedCredentials: 'Included Credentials',
				credential: 'Credential',
				Scopes: {
					date: "Dates",
					grade: "Grades",
					subject: "Subjects"
				},
			}
		},
		Generic: {
			title: 'Title',
			description: 'Description'
		},
		Error: {
			title: "Error",
			SESSION_EXPIRED: "Your session has expired",
			UNAUTHORIZED: "Unauthorized",
			Issuance: {
				INIT_ERROR: "An error occured during the initialization of the issuance phase",
				CREDENTIAL_SELECTION_ERROR: "An error occured during the selections of credentials"
			},
			Verification: {
				GENERIC: "An error occured during the initialization of the credential exchange",
				SUBJECT_HAS_EXPIRED: "Subject has expired",
				SUBJECT_FETCH_FAILURE: "Could not fetch Verification Subjects",
				SUBJECT_UNAUTHORIZED_FAILURE: "You do not have access to this subject",
				PRESENTATION_DEF_FETCH_FAILURE: "Could not fetch Presentation Definition",
				PRESENTATION_DEFS_FETCH_FAILURE: "Could not fetch Presentation Definitions",
				NO_CREATE_SUBJECT_TITLE: "No Verification Subject Title given",
				VERIFICATION_SUBJECT_TITLE_ALREADY_EXISTS: "Verification Subject with given Title already exists",
				NO_CREATE_SUBJECT_PRESENTATION_DEFINITION: "No Verification Subject Presentation Definition given",
				SUBJECT_EDIT_FAILURE: "Could not update subject",
				VERIFIABLE_PRESENTATION_FETCH_FAILURE: "Could not fetch received Verifiable Presentations",
				VERIFIABLE_PRESENTATION_UNAUTHORIZED_FAILURE: "You do not have access to this Verifiable Presentation",
			},
			Organisation: {
				ORGANISATIONS_FETCH_FAILURE: "Could not fetch organisations",
				ORGANISATION_CREATE_FAILURE: "Could not create organisation",
				ORGANISATION_FETCH_FAILURE: "Could not fetch specific organisation",
				ORGANISATION_UNAUTHORIZED_FAILURE: "You do not have access to this organisation",
				ORGANISATION_UPDATE_FAILURE: "Could not update organisation"
			}
		},
		ReturnToMainPage: "Return to main page"
	},
	el: {
		Header: {
			issuer: "Εφαρμογη Υπογραφης Διπλωματων",
			verifier: "Εφαρμογη Επαλήθευσης Ψηφιακών Πιστοποιητικών",
			title: "eDiplomas"
		},
		Footer: {
			services: "Υπηρεσίες",
			documentation: "Τεκμηρίωση",
			adminLogin: "Σύνδεση Διαχειριστή",
			information: "Πληροφορίες",
			participatingInst: "Συμμετέχοντα Ιδρύματα",
			termsOfUse: "Όροι Χρήσης",
			contact: "Επικοινωνία",
			web: "Ιστός",
			emailForOrgs: "E-mail για Φορείς & ΑΕΙ"
		},
		Index: {
			header: "Πύλη Έκδοσης Ψηφιακών Πτυχίων (ΑΕΙ)",
			description1: "Το eDiplomas είναι μία εξουσιοδοτημένη εφαρμογή έκδοσης ψηφιακών πτυχίων απο Ελληνικά ΑΕΙ σε μορφή Verifiable Credentials. Μέσα απο αυτήν την πλατφόρμα, oι κάτοχοι πτυχίων ΑΕΙ μπορούν να αποκτήσουν τα ψηφιακά τους πτυχία μέσω του TAXISnet λογαριασμού τους",
			description2: "",
			description3: "",
			proceedButtonText: "Συνέχεια",
			leftSideDesc: "Είμαι φοιτητής ή απόφοιτος",
			rightSideDesc: "Είμαι εκπρόσωπος φορέα",
		},
		Holder: {
			actions: "Ενέργειες Κατόχου",
			issue: {
				title: "Έκδοση",
				desc: "Θέλω να λάβω ένα ψηφιακό πιστοποιητικό",
			},
			verify: {
				title: "Επαλήθευση",
				desc: "Θέλω να παρουσιάσω ένα ψηφιακό πιστοποιητικό",
			},
		},
		FlowSelection: {
			header: "Επιλογή μεθόδου",
			description1: "Επιλέξτε μία απο τις παρακάτω μεθόδους για την λήψη των πτυχίων σας",
			crossDeviceDescription: "Choose this option if you have a wallet on your mobile.",
			sameDeviceDescription: "Choose this option if you have a wallet application on this device.",
		},
		CredentialSelection: {
			InstitutionSelection: {
				header: "Επιλογή Φορέα",
				description1: "Διάλεξε έναν φορέα, απο τον οποίο θέλετε να αποκτήσετε ένα πιστοποιητικό",
				placeholder1: "Πληκτρολoγίστε ένα όνομα φορέα",
				continue: "Συνεχίστε για την επιλογή πιστοποιητικών",
				warning1: "Παρακαλώ επιλέξτε έναν φορέα"
			}
		},
		Login: {
			title: "Σύνδεση",
			description1: "Καλωσήρθατε! Επιλέξτε τρόπο σύνδεσης",
			taxis: "Σύνδεση μέσω TAXIS",
			local: "Σύνδεση",
			Error: {
				emptyUsername: "Συμπληρώστε το όνομα χρήστη",
				emptyPassword: "Συμπληρώστε τον κωδικό πρόσβασης",
				invalidCredentials: "Τα στοιχεία δεν είναι σωστά",
				networkError: "Σφάλμα δικτύου"
			}
		},
		Organisation: {
			Back: {
				verificationSubject: 'Παραλήπτης',
				organisation: 'Οργανισμός',
				organisations: 'Οργανισμοί'
			},
			Organisations: {
				title: 'Οργανισμοί',
				createNew: 'Δημιουργία νέου Οργανισμού',
				searchByTitle: 'Αναζήτηση ανά Όνομα',
				searchDesc: 'Φιλτράρισμα αποτελεσμάτων για',
				searchClear: 'Καθαρισμός αναζήτησης',
				id: 'ID',
				titleCol: 'Όνομα',
				representative: 'Διαχειριστής'
			},
			CreateOrganisation: {
				header: 'Δημιουργία Οργανισμού',
				title: 'Τίτλος',
				invalidTitle: 'Παρακαλώ συμπληρώστε το όνομα του οργανισμού',
				duplicateTitle: 'Υπάρχει ήδη Οργανισμός με την παραπάνω ονομασία',
				description: 'Περιγραφή',
				identifier: 'Αναγνωριστικό Εκπροσώπου',
				invalidIdentifier: 'Παρακαλώ συμπληρώστε το αναγνωριστικό του εκπροσώπου του οργανισμού',
				details: 'Βασικά Στοιχεία Επικοινωνίας',
				fullname: 'Ονοματεπώνυμο',
				email: 'Διεύθυνση Ηλ. Ταχυδρομείου',
				phone: 'Τηλέφωνο Επικοινωνίας',
				create: 'Δημιουργία Οργανισμού',
				back: 'Πίσω'
			},
			CreateSubject: {
				header: 'Δημιουργία Παραλήπτη',
				definition: {
					stepTitle: 'Presentation Definition',
					header: 'Presentation Definition',
					description: 'Επιλογή Presentation Definition',
					create: 'Δημιουργία Presentation Definition'
				},
				details: {
					stepTitle: 'Λεπτομέρειες',
					header: 'Λεπτομέρειες Παραλήπτη',
					title: 'Τίτλος',
					feedback: 'Παρακαλώ δώστε έναν τίτλο παραλήπτη',
					description: 'Περιγραφή'
				},
				properties: {
					stepTitle: 'Ιδιότητες',
					header: 'Ιδιότητες Παραλήπτη',
					visibility: 'Ορατότητα',
					public: 'Ορατός (Δημόσιος)',
					private: 'Κρυμμένος (Ιδιωτικός)'
				},
				back: 'Πίσω',
				next: 'Επόμενο',
				submit: 'Δημιουργία'
			},
			CreateDefinition: {
				header: 'Δημιουργία Presentation Definition',
				title: 'Τίτλος',
				type: 'Επιλογή είδους πιστοποιητικού',
				schema: 'Επιλογή JSON Schema',
				create: 'Δημιουργία Presentation Definition',
				warning1: 'Δεν επιλέχθηκε κάποιος τύπος πιστοποιητικού',
				back: 'Πίσω'
			},
			Organisation: {
				updateAlert: 'Τα στοιχεία επικοινωνίας ανανεώθηκαν με επιτυχία',
				title: 'Οργανισμός',
				details: {
					header: 'Βασικά Στοιχεία Επικοινωνίας',
					name: 'Ονοματεπώνυμο Εκπροσώπου',
					phone: 'Τηλέφωνο Επικοινωνίας',
					email: 'Διεύθυνση Ηλ. Ταχυδρομείου',
					update: 'Ανανέωση στοιχείων επικοινωνίας',
					error: {
						name: 'Παρακαλώ συμπληρώστε το όνομα ενός διαχειριστή',
						phone: 'Παρακαλώ συμπληρώστε σωστό τηλέφωνο',
						email: 'Παρακαλώ συμπληρώστε σωστή διεύθυνση ηλεκτρονικού ταχυδρομείου'
					}
				},
				subjects: 'Παραλήπτες',
				addSubject: 'Προσθήκη Παραλήπτη',
				subject: {
					definition: 'Άνοιγμα Presentation Definition',
					expDate: 'Λήγει στις',
					noExpDate: 'Χωρίς Ημερομηνία Λήξης',
					visibility: 'Ορατότητα:',
					public: 'Δημόσια',
					private: 'Ιδιωτική',
					definitionTitle: 'Presentation Definition'
				}
			},
			Subject: {
				updateAlert: 'Τα στοιχεία ανανεώθηκαν με επιτυχία',
				title: 'Παραλήπτης',
				details: {
					header: 'Στοιχεία Παραλήπτη',
					titleError: 'Παρακαλώ επιλέξτε έναν έγκυρο Τίτλο Παραλήπτη',
					expandDef: 'Άνοιγμα Presentation Definition',
					visibility: 'Ορατότητα',
					visible: 'Ορατό (Δημόσιο)',
					hidden: 'Κρυφό (Ιδιωτικό)',
					expiration: 'Λήξη',
					never: 'Ποτέ',
					expirationError: 'Παρακαλώ συμπληρώστε σωστή ημερομηνία λήξης',
					expireNow: 'Λήξη Τώρα',
					update: 'Ενημέρωση Στοιχείων Παραλήπτη'
				},
				presentationDefinition: 'Presentation Definition',
				receivedPresentation: 'Ληφθείσες Παρουσιάσεις',
				showValid: 'Εμφάνιση Έγκυρων Παρουσιάσεων',
				showInvalid: 'Εμφάνιση Άκυρων Παρουσιάσεων',
				showingValid: 'Εμφανίζονται Έγκυρες Παρουσιάσεις',
				showingInvalid: 'Εμφανίζονται Άκυρες Παρουσιάσεις',
				id: 'ID',
				subject: 'Αποστολέας',
				date: 'Ημερομηνία'
			},
			VerifiablePresentation: {
				title: 'Ψηφιακή Παρουσίαση',
				copyMessage: 'Αντιγραφή ακατέργαστης παρουσίασης',
				copyAlertSuccess: 'Η ψηφιακή παρουσίαση αντιγράφηκε επιτυχώς',
				copyAlertFail: 'Σφάλμα αντιγραφης ψηφιακής παρουσίασης',
				includedCredentials: 'Περιεχόμενα Πιστοποιητικά',
				credential: 'Πιστοποιητικό',
				Scopes: {
					date: "Ημερομηνίες",
					grade: "Βαθμοί",
					subject: "Μαθήματα"
				}
			},
		},
		Generic: {
			title: 'Τίτλος',
			description: 'Περιγραφή'
		},
		Error: {
			title: "Σφάλμα",
			SESSION_EXPIRED: "Η σύνδεσή σας έχει λήξει",
			UNAUTHORIZED: "Μη εξουσιοδοτημένος",
			Issuance: {
				INIT_ERROR: "Παρουσιάστηκε σφάλμα κατα την αρχικοποίηση της φάσης λήψης πιστοποιητικών",
				CREDENTIAL_SELECTION_ERROR: "Παρουσιάστηκε σφάλμα κατα την επιλογή των πιστοποιητικών"
			},
			Verification: {
				GENERIC: "Παρουσιάστηκε σφάλμα κατα την έναρξη της ανταλλαγής πιστοποιητικών",
				SUBJECT_HAS_EXPIRED: "Έχει λήξει αυτός ο σύνδεσμος για την λήψη πιστοποιητικών",
				SUBJECT_FETCH_FAILURE: "Αδυναμία εύρεσης παραληπτών πιστοποιητικού",
				SUBJECT_UNAUTHORIZED_FAILURE: "Δεν έχετε πρόσβαση στον παραλήπτη",
				PRESENTATION_DEF_FETCH_FAILURE: "Αδυναμία επαλήθευσης πιστοποιητικού",
				PRESENTATION_DEFS_FETCH_FAILURE: "Αδυναμία λήψης πιστοποιητικών",
				NO_CREATE_SUBJECT_TITLE: "Δεν δόθηκε τίτλος παραλήπτη",
				VERIFICATION_SUBJECT_TITLE_ALREADY_EXISTS: "Υπάρχει ήδη παραλήπτης με τον ίδιο Τίτλο",
				NO_CREATE_SUBJECT_PRESENTATION_DEFINITION: "Δεν δόθηκαν πληροφορίες επαλήθευσης πιστοποιητικών παραλήπτη",
				SUBJECT_EDIT_FAILURE: "Αδυναμία επεξεργασίας παραλήπτη",
				VERIFIABLE_PRESENTATION_FETCH_FAILURE: "Αδυναμία λήψης παρουσιάσεων",
				VERIFIABLE_PRESENTATION_UNAUTHORIZED_FAILURE: "Δεν έχετε πρόσβαση στην παρουσίαση",
			},
			Organisation: {
				ORGANISATIONS_FETCH_FAILURE: "Αδυναμία εύρεσης οργανισμών",
				ORGANISATION_CREATE_FAILURE: "Αδυναμία δημιουργίας οργανισμού",
				ORGANISATION_FETCH_FAILURE: "Αδυναμία εύρεσης οργανισμού",
				ORGANISATION_UNAUTHORIZED_FAILURE: "Δεν έχετε πρόσβαση στον οργανισμό",
				ORGANISATION_UPDATE_FAILURE: "Αδυναμία ενημέρωσης οργανισμού"
			}
		},
		ReturnToMainPage: "Επιστρέψτε στην κεντρική σελίδα"
	}
}

export default locale;