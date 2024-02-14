#Identifier: =~"[a-zA-Z_][a-zA-Z0-9_]*"

#_NonNullByte:          #"[^\x00]"#
#NonNullString:         =~"\(#_NonNullByte)*"
#NonEmptyNonNullString: =~"\(#_NonNullByte)+"
#Path:                  #NonNullString

#EnvValue:          #NonNullString
#BashVarName:       #Identifier
#BashVarValue:      #NonNullString
#BashCommandString: #NonNullString

#Args: {
	[#Identifier]: *"" | #NonNullString
}

#_ImageName:   "[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*" // from distribution spec
#_ImageTag:    "[a-z0-9]+([._-][a-z0-9]+)*"
#_ImageDigest: "[a-f0-9]{64}"
#_ImageRef:    "\(#_ImageTag)(:\(#_ImageTag)|@sha256:\(#_ImageDigest))"

#ImageName:   =~"\(#_ImageName)"
#ImageDigest: =~"\(#_ImageDigest)"
#ImageRef:    =~"\(#_ImageRef)"

#_Semver: #"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"#
#Semver:  =~"\(#_Semver)"

#_Digits: "[0-9]*"
#Digits:  =~"\(#_Digits)"

#Map: {
	[#Identifier]: _
}

#EnvMap: #Map & {
	[#BashVarName]: #BashVarValue
}

#URLRegex:    =~"https?:\\/\\/[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)"
#CommitRegex: =~"[0-9a-f]{40}" | =~"[0-9a-f]{8}"

#MountSpec: {
	dest!: #Path
	spec!: #Source
}

#CacheDirConfig: {
	mode:               string
	key:                *#Source.path | #Path
	include_distro_key: *false | true
	include_arch_key:   *false | true
}

#BuildStep: {
	"command": #BashCommandString
	env?:      #EnvMap
}

#CacheDirMap: #Map & {
	[#Identifier]: #CacheDirConfig
}

#ImageCmd: {
	dir?: #Path
	mounts?: [...#MountSpec]
	cache_dirs?: #Map & {[string]: #CacheDirConfig}
	env?: #EnvMap
	steps!: [...#BuildStep]
}

#ImageSource: {
	ref:  #ImageRef
	cmd?: #ImageCmd
}

#GitSource: {
	url!:       #URLRegex
	commit?:    string // require commit hash, not tag, for auditability
	keepGitDir: *true | false
}

#ContextSource: {
	name: *"context" | #NonEmptyNonNullString
}

#HTTPSource: {
	url: #URLRegex
}

#DefaultContext: #ContextSource & {
	name: "context"
}

#InlineOrDockerfile: {inline: #NonEmptyNonNullString} | {dockerfile: #NonEmptyNonNullString}

#BuildSource: {
	source: *#DefaultContext | #Source
	#InlineOrDockerfile
}

#SourceVariantEntry:
	{image: #ImageSource} |
	{git: #GitSource} |
	{http: #HTTPSource} |
	{build: #BuildSource} |
	{context: #ContextSource}

#Source: {
	path: *"." | #NonNullString
	#SourceVariantEntry
	includes?: [...#NonEmptyNonNullString]
	excludes?: [...#NonEmptyNonNullString]
}

#SourceMap: {
	[#Identifier]: {
		#Source
	}
}

sourceMap: #SourceMap

doc: {
	args?: #Args
	#Metadata
	sources: #SourceMap
	...
}

#Metadata: {
	name:        #NonEmptyNonNullString
	version:     #Semver | "${VERSION}"
	revision:    *"" | #Digits | "${REVISION}"
	packager:    #NonEmptyNonNullString
	vendor:      #NonEmptyNonNullString
	license:     #NonEmptyNonNullString
	description: #NonEmptyNonNullString
	website:     #NonEmptyNonNullString
}

// source: #Map & {[#Identifier]: #Source}
