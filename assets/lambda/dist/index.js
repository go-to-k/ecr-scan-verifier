"use strict";var E=Object.defineProperty;var U=Object.getOwnPropertyDescriptor;var H=Object.getOwnPropertyNames;var V=Object.prototype.hasOwnProperty;var K=(e,o)=>{for(var n in o)E(e,n,{get:o[n],enumerable:!0})},j=(e,o,n,t)=>{if(o&&typeof o=="object"||typeof o=="function")for(let s of H(o))!V.call(e,s)&&s!==n&&E(e,s,{get:()=>o[s],enumerable:!(t=U(o,s))||t.enumerable});return e};var X=e=>j(E({},"__esModule",{value:!0}),e);var rn={};K(rn,{handler:()=>_});module.exports=X(rn);var b=require("@aws-sdk/client-ecr"),O=new b.ECRClient,z=e=>new Promise(o=>setTimeout(o,e)),L=e=>e.startsWith("sha256:")?{imageDigest:e}:{imageTag:e},k=async(e,o,n,t,s)=>{let i=L(o);console.log(`Starting image scan for ${e}...`);try{await O.send(new b.StartImageScanCommand({repositoryName:e,imageId:i})),console.log("Image scan started successfully.")}catch(a){if(a.name==="LimitExceededException"||a.message&&a.message.includes("scan frequency limit"))console.log("Scan already in progress or recently completed, polling for results...");else throw a.name==="ValidationException"&&a.message&&a.message.includes("This feature is disabled")?new Error("StartImageScan is disabled because Enhanced scanning (Amazon Inspector) is enabled on this account. Use ScanConfig.enhanced() instead of ScanConfig.basic()."):a}return N(e,o,n,t,s)},N=async(e,o,n,t,s)=>{let i=L(o);for(let a=0;a<s;a++){console.log(`Polling scan results (attempt ${a+1}/${s})...`);try{let c=await q(e,i),r=c.rawResponse.imageScanStatus?.status;if(r==="COMPLETE"||r==="ACTIVE")return console.log(`Scan completed with status: ${r}`),c;if(r==="FAILED"){let u=c.rawResponse.imageScanStatus?.description||"Unknown error";throw new Error(`ECR image scan failed: ${u}`)}if(r==="UNSUPPORTED_IMAGE")throw new Error("ECR image scan failed: Image is not supported for scanning.");console.log(`Scan status: ${r}, waiting ${t}s...`)}catch(c){throw c.name==="ScanNotFoundException"?new Error("No scan results found for the image. Ensure that image scanning is enabled for this repository. If using Enhanced scanning (Amazon Inspector), verify that the repository is included in Inspector's coverage."):c}await z(t*1e3)}throw new Error(`ECR image scan timed out after ${s*t} seconds. The scan may still be in progress. Check the ECR console for results.`)},q=async(e,o)=>{let n=[],t=[],s,i;do{let r=await O.send(new b.DescribeImageScanFindingsCommand({repositoryName:e,imageId:o,nextToken:s,maxResults:1e3}));i=r,r.imageScanFindings?.findings&&n.push(...r.imageScanFindings.findings),r.imageScanFindings?.enhancedFindings&&t.push(...r.imageScanFindings.enhancedFindings),s=r.nextToken}while(s);let a=i?.imageScanFindings?.findingSeverityCounts?Object.fromEntries(Object.entries(i.imageScanFindings.findingSeverityCounts).map(([r,u])=>[r,u??0])):{};return{scanType:t.length>0?"ENHANCED":"BASIC",status:i?.imageScanStatus?.status??"UNKNOWN",basicFindings:n,enhancedFindings:t,severityCounts:a,rawResponse:i}};var x=(e,o,n)=>{let t=new Set(n),s=new Set(o);return e.scanType==="ENHANCED"?Y(e,s,t):J(e,s,t)},J=(e,o,n)=>{let t=e.basicFindings.filter(c=>!n.has(c.name||"")),s={},i=!1;for(let c of t){let r=c.severity||"UNDEFINED";s[r]=(s[r]||0)+1,o.has(r)&&(i=!0)}let a=R(s);return{hasVulnerabilities:i,summary:a,filteredSeverityCounts:s}},Y=(e,o,n)=>{let t=e.enhancedFindings.filter(c=>{if(n.has(c.findingArn||""))return!1;let r=c.packageVulnerabilityDetails?.vulnerabilityId;return!(r&&n.has(r))}),s={},i=!1;for(let c of t){let r=c.severity||"UNDEFINED";s[r]=(s[r]||0)+1,o.has(r)&&(i=!0)}let a=R(s);return{hasVulnerabilities:i,summary:a,filteredSeverityCounts:s}},R=e=>["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL","UNDEFINED"].filter(n=>e[n]).map(n=>`${n}: ${e[n]}`).join(", "),F=(e,o,n,t)=>{let s=["=== ECR Image Scan Results ===",`Repository: ${n}`,`Image: ${t}`,`Scan Type: ${e.scanType}`,`Scan Status: ${e.status}`,"","--- Severity Summary ---"];if(o.summary?s.push(o.summary):s.push("No vulnerabilities found."),s.push(""),e.scanType==="BASIC"||e.scanType==="ENHANCED"){let i=e.scanType==="ENHANCED"?e.enhancedFindings:e.basicFindings;if(i.length>0){s.push(`--- Findings (${i.length} total) ---`);let a=["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL","UNDEFINED"];for(let c of a){let r=e.scanType==="ENHANCED"?e.enhancedFindings.filter(u=>u.severity===c):e.basicFindings.filter(u=>u.severity===c);if(r.length>0){s.push(`
[${c}] (${r.length})`);for(let u of r.slice(0,20))if(e.scanType==="ENHANCED"){let m=u,p=m.packageVulnerabilityDetails?.vulnerabilityId||"N/A",g=m.packageVulnerabilityDetails?.vulnerablePackages?.[0],l=g?`${g.name}@${g.version}`:"N/A";s.push(`  ${p} | Package: ${l}`)}else{let m=u;s.push(`  ${m.name||"N/A"} | ${m.description?.substring(0,100)||"N/A"}`)}r.length>20&&s.push(`  ... and ${r.length-20} more`)}}}}return s.join(`
`)};var S=require("@aws-sdk/client-cloudwatch-logs"),T=new S.CloudWatchLogsClient,v=async(e,o,n,t)=>{let s=t.replace(/:/g,",").replace(/\//g,"_"),i=`${s}/findings`,a=`${s}/summary`,c=new Date().getTime();return await P(n.logGroupName,i,c,e),await P(n.logGroupName,a,c,o),console.log(`Scan logs output to the log group: ${n.logGroupName}
  findings stream: ${i}
  summary stream: ${a}`),{type:"cloudwatch",logGroupName:n.logGroupName,findingsLogStreamName:i,summaryLogStreamName:a}},A=1048576,Q=e=>{let n=new TextEncoder().encode(e);if(n.length<=A)return[e];let t=[],s=0,a=A-20;for(;s<n.length;){let c=n.slice(s,s+a),r=new TextDecoder("utf-8",{fatal:!1});t.push(r.decode(c)),s+=a}return t},P=async(e,o,n,t)=>{try{await T.send(new S.CreateLogStreamCommand({logGroupName:e,logStreamName:o}))}catch(u){if(u instanceof S.ResourceAlreadyExistsException)console.log(`Log stream ${o} already exists in log group ${e}.`);else throw u}let s=Q(t),i=s.length;i>1&&console.log(`Message size exceeds 1 MB limit. Splitting into ${i} chunks.`);let a=s.map((u,m)=>({timestamp:n+m,message:i>1?`[part ${m+1}/${i}] ${u}`:u})),c={logGroupName:e,logStreamName:o,logEvents:a},r=new S.PutLogEventsCommand(c);await T.send(r)};var h=require("@aws-sdk/client-s3");var I=new h.S3Client,D=async(e,o,n,t,s)=>{let i=new Date().toISOString(),a=t.replace(/:/g,"/").replace(/\//g,"_"),r=`${n.prefix?n.prefix.endsWith("/")?n.prefix:`${n.prefix}/`:""}${a}/${i}`,u=`${r}/findings.json`,m=`${r}/summary.txt`,p=[I.send(new h.PutObjectCommand({Bucket:n.bucketName,Key:u,Body:e,ContentType:"application/json"})),I.send(new h.PutObjectCommand({Bucket:n.bucketName,Key:m,Body:o,ContentType:"text/plain"}))],g;if(s){let l=s.format==="SPDX_2_3"?"spdx.json":"cyclonedx.json";g=`${r}/sbom.${l}`,p.push(I.send(new h.PutObjectCommand({Bucket:n.bucketName,Key:g,Body:s.content,ContentType:"application/json"})))}return await Promise.all(p),console.log(g?`Scan logs and SBOM output to S3:
  findings: s3://${n.bucketName}/${u}
  summary: s3://${n.bucketName}/${m}
  SBOM: s3://${n.bucketName}/${g}`:`Scan logs output to S3:
  findings: s3://${n.bucketName}/${u}
  summary: s3://${n.bucketName}/${m}`),{type:"s3",bucketName:n.bucketName,findingsKey:u,summaryKey:m,sbomKey:g}};var C=require("@aws-sdk/client-sns"),Z=new C.SNSClient,G=async(e,o,n,t)=>{let s="",i="";if(t.type==="cloudwatch")s=`CloudWatch Logs:
  Log Group: ${t.logGroupName}
  Findings Stream: ${t.findingsLogStreamName}
  Summary Stream: ${t.summaryLogStreamName}`,i=`- View findings:
\`\`\`
aws logs tail ${t.logGroupName} --log-stream-names ${t.findingsLogStreamName} --since 1h
\`\`\`

- View summary:
\`\`\`
aws logs tail ${t.logGroupName} --log-stream-names ${t.summaryLogStreamName} --since 1h
\`\`\``;else if(t.type==="s3"){let m=t.sbomKey?`
  SBOM: s3://${t.bucketName}/${t.sbomKey}`:"";s=`S3:
  Bucket: ${t.bucketName}
  findings: s3://${t.bucketName}/${t.findingsKey}
  summary: s3://${t.bucketName}/${t.summaryKey}${m}`;let p=t.sbomKey?`

- View SBOM:
\`\`\`
aws s3 cp s3://${t.bucketName}/${t.sbomKey} -
\`\`\``:"";i=`- View findings:
\`\`\`
aws s3 cp s3://${t.bucketName}/${t.findingsKey} -
\`\`\`

- View summary:
\`\`\`
aws s3 cp s3://${t.bucketName}/${t.summaryKey} -
\`\`\`${p}`}else t.type==="default"&&(s=`CloudWatch Logs:
  Log Group: ${t.logGroupName}`,i=`\`\`\`
aws logs tail ${t.logGroupName} --since 1h
\`\`\``);let a=`${s}

How to view logs:
${i}`,c={version:"1.0",source:"custom",content:{title:"Image Scanner with ECR - Vulnerability Alert",description:`## Scanned Image
${n}

## Scan Logs
${a}

## Details
${o}`}},r=`Image Scanner with ECR detected vulnerabilities in ${n}

${a}

${o}`,u={default:r,email:r,https:JSON.stringify(c)};try{await Z.send(new C.PublishCommand({TopicArn:e,Message:JSON.stringify(u),MessageStructure:"json"})),console.log(`Vulnerability notification sent to SNS topic: ${e}`)}catch(m){console.error(`Failed to send vulnerability notification to SNS: ${m}`)}};var y=require("@aws-sdk/client-cloudformation"),nn=new y.CloudFormationClient,B=async e=>{let o=new y.DescribeStacksCommand({StackName:e}),n=await nn.send(o);if(n.Stacks&&n.Stacks.length>0){let t=n.Stacks[0].StackStatus;return t===y.ResourceStatus.ROLLBACK_IN_PROGRESS||t===y.ResourceStatus.UPDATE_ROLLBACK_IN_PROGRESS}throw new Error(`Stack not found or no stacks returned from DescribeStacks command, stackId: ${e}`)};var f=require("@aws-sdk/client-inspector2"),w=require("@aws-sdk/client-s3"),M=new f.Inspector2Client,en=new w.S3Client,tn=e=>new Promise(o=>setTimeout(o,e)),W=async(e,o,n,t,s)=>{let i=n==="SPDX_2_3"?f.SbomReportFormat.SPDX_2_3:f.SbomReportFormat.CYCLONEDX_1_4;console.log(`Starting SBOM export for ${e} with format ${n}...`);let a={ecrRepositoryName:[{comparison:"EQUALS",value:e}],...o?{ecrImageTags:[{comparison:"EQUALS",value:o}]}:{}},r=(await M.send(new f.CreateSbomExportCommand({reportFormat:i,s3Destination:{bucketName:t,keyPrefix:`sbom-exports/${e}`,kmsKeyArn:s},resourceFilterCriteria:a}))).reportId;if(!r)throw new Error("CreateSbomExport did not return a reportId.");console.log(`SBOM export started with reportId: ${r}`);let u=60,m=5;for(let p=0;p<u;p++){let g=await M.send(new f.GetSbomExportCommand({reportId:r})),l=g.status;if(console.log(`SBOM export status: ${l} (attempt ${p+1}/${u})`),l==="SUCCEEDED"){let d=g.s3Destination?.keyPrefix,$=g.s3Destination?.bucketName;if(!$||!d)throw new Error("SBOM export succeeded but S3 destination is missing.");return{sbomContent:await sn($,d),format:n}}if(l==="FAILED"){let d=g.filterCriteria;throw new Error(`SBOM export failed. Filter criteria: ${JSON.stringify(d)}`)}if(l==="CANCELLED")throw new Error("SBOM export was cancelled.");await tn(m*1e3)}throw new Error(`SBOM export timed out after ${u*m} seconds.`)},sn=async(e,o)=>await(await en.send(new w.GetObjectCommand({Bucket:e,Key:o}))).Body?.transformToString()??"";var _=async function(e){let o=e.RequestType,n=e.ResourceProperties;if(!n.addr||!n.repositoryName)throw new Error("addr and repositoryName are required.");let t={PhysicalResourceId:n.addr,Data:{}};if(o!=="Create"&&o!=="Update")return t;let s=5,i=60,a=`${n.repositoryName}:${n.imageTag}`,c;n.startScan==="true"?c=await k(n.repositoryName,n.imageTag,n.scanType,s,i):c=await N(n.repositoryName,n.imageTag,n.scanType,s,i);let r=x(c,n.severity,n.ignoreFindings),u;if(n.sbom)if(n.scanType==="ENHANCED")try{let d=await W(n.repositoryName,n.imageTag,n.sbom.format,n.sbom.bucketName,n.sbom.kmsKeyArn);u={content:d.sbomContent,format:d.format}}catch(d){console.error(`SBOM export failed (non-fatal): ${d}`)}else console.log("SBOM export is only available with Enhanced scanning. Skipping SBOM generation.");let m=JSON.stringify(c.rawResponse.imageScanFindings,null,2),p=F(c,r,n.repositoryName,n.imageTag),g=await on(m,p,a,n.output,n.defaultLogGroupName,u);if(!r.hasVulnerabilities)return t;let l=`ECR Image Scan found vulnerabilities.
Image: ${a}
Scan Type: ${c.scanType}
Findings: ${r.summary}
See scan logs for details.`;if(n.vulnsTopicArn&&await G(n.vulnsTopicArn,l,a,g),n.failOnVulnerability==="false")return t;if(n.suppressErrorOnRollback==="true"&&await B(e.StackId))return console.log(`Vulnerabilities detected, but suppressing errors during rollback (suppressErrorOnRollback=true).
${l}`),t;throw new Error(l)},on=async(e,o,n,t,s,i)=>{switch(t?.type){case"cloudWatchLogs":return await v(e,o,t,n);case"s3":return await D(e,o,t,n,i);default:return console.log(`summary:
`+o),console.log(`findings:
`+e),{type:"default",logGroupName:s}}};0&&(module.exports={handler});
