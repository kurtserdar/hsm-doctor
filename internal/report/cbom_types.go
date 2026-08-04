package report

// Hand-written subset of the CycloneDX 1.6 schema, limited to the
// cryptographic-asset model this tool emits. Kept dependency-free, mirroring
// the SARIF emitter.

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Version      int             `json:"version"`
	Metadata     *cdxMetadata    `json:"metadata,omitempty"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Tools     *cdxTools     `json:"tools,omitempty"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components,omitempty"`
}

type cdxComponent struct {
	Type             string               `json:"type"`
	BOMRef           string               `json:"bom-ref,omitempty"`
	Name             string               `json:"name"`
	Version          string               `json:"version,omitempty"`
	CryptoProperties *cdxCryptoProperties `json:"cryptoProperties,omitempty"`
	Properties       []cdxProperty        `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxCryptoProperties struct {
	AssetType                       string                         `json:"assetType"`
	AlgorithmProperties             *cdxAlgorithmProperties        `json:"algorithmProperties,omitempty"`
	CertificateProperties           *cdxCertificateProperties      `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *cdxRelatedCryptoMaterialProps `json:"relatedCryptoMaterialProperties,omitempty"`
	OID                             string                         `json:"oid,omitempty"`
}

type cdxAlgorithmProperties struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	NISTQuantumSecurityLevel int      `json:"nistQuantumSecurityLevel,omitempty"`
}

type cdxCertificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
}

type cdxRelatedCryptoMaterialProps struct {
	Type         string        `json:"type,omitempty"`
	ID           string        `json:"id,omitempty"`
	Size         int           `json:"size,omitempty"`
	State        string        `json:"state,omitempty"`
	AlgorithmRef string        `json:"algorithmRef,omitempty"`
	SecuredBy    *cdxSecuredBy `json:"securedBy,omitempty"`
}

type cdxSecuredBy struct {
	Mechanism string `json:"mechanism,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}
