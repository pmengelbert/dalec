#Identifier:  =~"[a-zA-Z_][a-zA-Z0-9_]*"
#BashVarName: #Identifier

#_NonNullByte:          #"[^\x00]"#
#NonNullString:         *"" | =~"\(#_NonNullByte)*"
#NonEmptyNonNullString: =~"\(#_NonNullByte)+"
#Path:                  #NonNullString
#EnvValue:              #NonNullString
#BashVarValue:          #NonNullString
#BashCommandString:     #NonNullString

#_ImageName:   "[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*" // from distribution spec
#_ImageTag:    "[a-z0-9]+([._-][a-z0-9]+)*"
#_ImageDigest: "[a-f0-9]{64}"
#_ImageRef:    "\(#_ImageTag)(:\(#_ImageTag)|@sha256:\(#_ImageDigest))"

#ImageName:   =~"\(#_ImageName)"
#ImageDigest: =~"\(#ImageDigest)"
#ImageRef:    =~"\(#_ImageRef)"

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

srcMap: #SourceMap & {
	hello: {
		path: "hey"
		image: {
			ref: "hi:there"
			cmd: {
				steps: [
					{
						"command": "/bin/true"
					},
				]
			}
		}
	}
}

s: #SourceMap & {
	test: {
		// path: "/bar"
		image: {
			ref: "busybox:latest"
			cmd: {
				mounts: [
					{
						dest: "/foo"
						spec: {
							context: {
								name: "hey"
							}
						}},
				]
				steps: [
					{
						env: {
							FILE_TO_IMPORT: "${file_to_import}"
						}
						"command": "set -e; mkdir -p /bar; cp \"/foo/${FILE_TO_IMPORT}\" \"/bar/${FILE_TO_IMPORT}\""
					},
				]
			}
		}
	}
}

// source: #Map & {[#Identifier]: #Source}
