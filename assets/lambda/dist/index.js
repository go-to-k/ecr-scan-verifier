"use strict";var O=Object.defineProperty;var K=Object.getOwnPropertyDescriptor;var V=Object.getOwnPropertyNames;var H=Object.prototype.hasOwnProperty;var j=(t,o)=>{for(var n in o)O(t,n,{get:o[n],enumerable:!0})},X=(t,o,n,e)=>{if(o&&typeof o=="object"||typeof o=="function")for(let s of V(o))!H.call(t,s)&&s!==n&&O(t,s,{get:()=>o[s],enumerable:!(e=K(o,s))||e.enumerable});return t};var z=t=>X(O({},"__esModule",{value:!0}),t);var rn={};j(rn,{handler:()=>U});module.exports=z(rn);var C=require("@aws-sdk/client-ecr"),L=new C.ECRClient,N=t=>new Promise(o=>setTimeout(o,t)),k=t=>t.startsWith("sha256:")?{imageDigest:t}:{imageTag:t},x=async(t,o,n,e,s)=>{let i=k(o);console.log(`Starting image scan for ${t}...`);try{await L.send(new C.StartImageScanCommand({repositoryName:t,imageId:i})),console.log("Image scan started successfully.")}catch(a){if(a.name==="LimitExceededException"||a.message&&a.message.includes("scan frequency limit"))console.log("Scan already in progress or recently completed, polling for results...");else throw a.name==="ValidationException"&&a.message&&a.message.includes("This feature is disabled")?new Error("StartImageScan is disabled because Enhanced scanning (Amazon Inspector) is enabled on this account. Use ScanConfig.enhanced() instead of ScanConfig.basic()."):a}return $(t,o,n,e,s)},$=async(t,o,n,e,s)=>{let i=k(o);for(let a=0;a<s;a++){console.log(`Polling scan results (attempt ${a+1}/${s})...`);try{let c=await q(t,i),r=c.rawResponse.imageScanStatus?.status;if(r==="COMPLETE"||r==="ACTIVE")return console.log(`Scan completed with status: ${r}`),c;if(r==="FAILED"){let u=c.rawResponse.imageScanStatus?.description||"Unknown error";throw new Error(`ECR image scan failed: ${u}`)}if(r==="UNSUPPORTED_IMAGE")throw new Error("ECR image scan failed: Image is not supported for scanning.");console.log(`Scan status: ${r}, waiting ${e}s...`)}catch(c){if(c.name==="ScanNotFoundException"){if(a<s-1){console.log(`Scan not found yet (attempt ${a+1}/${s}), waiting ${e}s before retrying...`),await N(e*1e3);continue}throw new Error(`No scan results found for the image after ${s*e} seconds. Ensure that image scanning is enabled for this repository. If using Enhanced scanning (Amazon Inspector), verify that the repository is included in Inspector's coverage.`)}throw c}await N(e*1e3)}throw new Error(`ECR image scan timed out after ${s*e} seconds. The scan may still be in progress. Check the ECR console for results.`)},q=async(t,o)=>{let n=[],e=[],s,i;do{let r=await L.send(new C.DescribeImageScanFindingsCommand({repositoryName:t,imageId:o,nextToken:s,maxResults:1e3}));i=r,r.imageScanFindings?.findings&&n.push(...r.imageScanFindings.findings),r.imageScanFindings?.enhancedFindings&&e.push(...r.imageScanFindings.enhancedFindings),s=r.nextToken}while(s);let a=i?.imageScanFindings?.findingSeverityCounts?Object.fromEntries(Object.entries(i.imageScanFindings.findingSeverityCounts).map(([r,u])=>[r,u??0])):{};return{scanType:e.length>0?"ENHANCED":"BASIC",status:i?.imageScanStatus?.status??"UNKNOWN",basicFindings:n,enhancedFindings:e,severityCounts:a,rawResponse:i}};var R=(t,o,n)=>{let e=new Set(n),s=new Set(o);return t.scanType==="ENHANCED"?Y(t,s,e):J(t,s,e)},J=(t,o,n)=>{let e=t.basicFindings.filter(c=>!n.has(c.name||"")),s={},i=!1;for(let c of e){let r=c.severity||"UNDEFINED";s[r]=(s[r]||0)+1,o.has(r)&&(i=!0)}let a=F(s);return{hasVulnerabilities:i,summary:a,filteredSeverityCounts:s}},Y=(t,o,n)=>{let e=t.enhancedFindings.filter(c=>{if(n.has(c.findingArn||""))return!1;let r=c.packageVulnerabilityDetails?.vulnerabilityId;return!(r&&n.has(r))}),s={},i=!1;for(let c of e){let r=c.severity||"UNDEFINED";s[r]=(s[r]||0)+1,o.has(r)&&(i=!0)}let a=F(s);return{hasVulnerabilities:i,summary:a,filteredSeverityCounts:s}},F=t=>["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL","UNDEFINED"].filter(n=>t[n]).map(n=>`${n}: ${t[n]}`).join(", "),T=(t,o,n,e)=>{let s=["=== ECR Image Scan Results ===",`Repository: ${n}`,`Image: ${e}`,`Scan Type: ${t.scanType}`,`Scan Status: ${t.status}`,"","--- Severity Summary ---"];return o.summary?s.push(o.summary):s.push("No vulnerabilities found."),s.join(`
`)};var S=require("@aws-sdk/client-cloudwatch-logs"),P=new S.CloudWatchLogsClient,v=async(t,o,n,e)=>{let s=e.replace(/:/g,",").replace(/\//g,"_"),i=`${s}/findings`,a=`${s}/summary`,c=new Date().getTime();return await A(n.logGroupName,i,c,t),await A(n.logGroupName,a,c,o),console.log(`Scan logs output to the log group: ${n.logGroupName}
  findings stream: ${i}
  summary stream: ${a}`),{type:"cloudwatch",logGroupName:n.logGroupName,findingsLogStreamName:i,summaryLogStreamName:a}},G=1048576,Q=t=>{let n=new TextEncoder().encode(t);if(n.length<=G)return[t];let e=[],s=0,a=G-20;for(;s<n.length;){let c=n.slice(s,s+a),r=new TextDecoder("utf-8",{fatal:!1});e.push(r.decode(c)),s+=a}return e},A=async(t,o,n,e)=>{try{await P.send(new S.CreateLogStreamCommand({logGroupName:t,logStreamName:o}))}catch(u){if(u instanceof S.ResourceAlreadyExistsException)console.log(`Log stream ${o} already exists in log group ${t}.`);else throw u}let s=Q(e),i=s.length;i>1&&console.log(`Message size exceeds 1 MB limit. Splitting into ${i} chunks.`);let a=s.map((u,m)=>({timestamp:n+m,message:i>1?`[part ${m+1}/${i}] ${u}`:u})),c={logGroupName:t,logStreamName:o,logEvents:a},r=new S.PutLogEventsCommand(c);await P.send(r)};var h=require("@aws-sdk/client-s3");var I=new h.S3Client,B=async(t,o,n,e,s)=>{let i=new Date().toISOString(),a=e.replace(/:/g,"/").replace(/\//g,"_"),r=`${n.prefix?n.prefix.endsWith("/")?n.prefix:`${n.prefix}/`:""}${a}/${i}`,u=`${r}/findings.json`,m=`${r}/summary.txt`,d=[I.send(new h.PutObjectCommand({Bucket:n.bucketName,Key:u,Body:t,ContentType:"application/json"})),I.send(new h.PutObjectCommand({Bucket:n.bucketName,Key:m,Body:o,ContentType:"text/plain"}))],g;if(s){let l=s.format==="SPDX_2_3"?"spdx.json":"cyclonedx.json";g=`${r}/sbom.${l}`,d.push(I.send(new h.PutObjectCommand({Bucket:n.bucketName,Key:g,Body:s.content,ContentType:"application/json"})))}return await Promise.all(d),console.log(g?`Scan logs and SBOM output to S3:
  findings: s3://${n.bucketName}/${u}
  summary: s3://${n.bucketName}/${m}
  SBOM: s3://${n.bucketName}/${g}`:`Scan logs output to S3:
  findings: s3://${n.bucketName}/${u}
  summary: s3://${n.bucketName}/${m}`),{type:"s3",bucketName:n.bucketName,findingsKey:u,summaryKey:m,sbomKey:g}};var w=require("@aws-sdk/client-sns"),Z=new w.SNSClient,D=async(t,o,n,e)=>{let s="",i="";if(e.type==="cloudwatch")s=`CloudWatch Logs:
  Log Group: ${e.logGroupName}
  Findings Stream: ${e.findingsLogStreamName}
  Summary Stream: ${e.summaryLogStreamName}`,i=`- View findings:
\`\`\`
aws logs tail ${e.logGroupName} --log-stream-names ${e.findingsLogStreamName} --since 1h
\`\`\`

- View summary:
\`\`\`
aws logs tail ${e.logGroupName} --log-stream-names ${e.summaryLogStreamName} --since 1h
\`\`\``;else if(e.type==="s3"){let m=e.sbomKey?`
  SBOM: s3://${e.bucketName}/${e.sbomKey}`:"";s=`S3:
  Bucket: ${e.bucketName}
  findings: s3://${e.bucketName}/${e.findingsKey}
  summary: s3://${e.bucketName}/${e.summaryKey}${m}`;let d=e.sbomKey?`

- View SBOM:
\`\`\`
aws s3 cp s3://${e.bucketName}/${e.sbomKey} -
\`\`\``:"";i=`- View findings:
\`\`\`
aws s3 cp s3://${e.bucketName}/${e.findingsKey} -
\`\`\`

- View summary:
\`\`\`
aws s3 cp s3://${e.bucketName}/${e.summaryKey} -
\`\`\`${d}`}else e.type==="default"&&(s=`CloudWatch Logs:
  Log Group: ${e.logGroupName}`,i=`\`\`\`
aws logs tail ${e.logGroupName} --since 1h
\`\`\``);let a=`${s}

How to view logs:
${i}`,c={version:"1.0",source:"custom",content:{title:"Image Scanner with ECR - Vulnerability Alert",description:`## Scanned Image
${n}

## Scan Logs
${a}

## Details
${o}`}},r=`Image Scanner with ECR detected vulnerabilities in ${n}

${a}

${o}`,u={default:r,email:r,https:JSON.stringify(c)};try{await Z.send(new w.PublishCommand({TopicArn:t,Message:JSON.stringify(u),MessageStructure:"json"})),console.log(`Vulnerability notification sent to SNS topic: ${t}`)}catch(m){console.error(`Failed to send vulnerability notification to SNS: ${m}`)}};var b=require("@aws-sdk/client-cloudformation"),nn=new b.CloudFormationClient,_=async t=>{let o=new b.DescribeStacksCommand({StackName:t}),n=await nn.send(o);if(n.Stacks&&n.Stacks.length>0){let e=n.Stacks[0].StackStatus;return e===b.ResourceStatus.ROLLBACK_IN_PROGRESS||e===b.ResourceStatus.UPDATE_ROLLBACK_IN_PROGRESS}throw new Error(`Stack not found or no stacks returned from DescribeStacks command, stackId: ${t}`)};var p=require("@aws-sdk/client-inspector2"),E=require("@aws-sdk/client-s3"),W=new p.Inspector2Client,en=new E.S3Client,tn=t=>new Promise(o=>setTimeout(o,t)),M=async(t,o,n,e,s)=>{let i=n==="SPDX_2_3"?p.SbomReportFormat.SPDX_2_3:p.SbomReportFormat.CYCLONEDX_1_4;console.log(`Starting SBOM export for ${t} with format ${n}...`);let a={ecrRepositoryName:[{comparison:"EQUALS",value:t}],...o?{ecrImageTags:[{comparison:"EQUALS",value:o}]}:{}},r=(await W.send(new p.CreateSbomExportCommand({reportFormat:i,s3Destination:{bucketName:e,keyPrefix:`sbom-exports/${t}`,kmsKeyArn:s},resourceFilterCriteria:a}))).reportId;if(!r)throw new Error("CreateSbomExport did not return a reportId.");console.log(`SBOM export started with reportId: ${r}`);let u=60,m=5;for(let d=0;d<u;d++){let g=await W.send(new p.GetSbomExportCommand({reportId:r})),l=g.status;if(console.log(`SBOM export status: ${l} (attempt ${d+1}/${u})`),l==="SUCCEEDED"){let f=g.s3Destination?.keyPrefix,y=g.s3Destination?.bucketName;if(!y||!f)throw new Error("SBOM export succeeded but S3 destination is missing.");return{sbomContent:await sn(y,f),format:n}}if(l==="FAILED"){let f=g.filterCriteria;throw new Error(`SBOM export failed. Filter criteria: ${JSON.stringify(f)}`)}if(l==="CANCELLED")throw new Error("SBOM export was cancelled.");await tn(m*1e3)}throw new Error(`SBOM export timed out after ${u*m} seconds.`)},sn=async(t,o)=>await(await en.send(new E.GetObjectCommand({Bucket:t,Key:o}))).Body?.transformToString()??"";var U=async function(t){let o=t.RequestType,n=t.ResourceProperties;if(!n.addr||!n.repositoryName)throw new Error("addr and repositoryName are required.");let e={PhysicalResourceId:n.addr,Data:{}};if(o!=="Create"&&o!=="Update")return e;let s=5,i=60,a=`${n.repositoryName}:${n.imageTag}`,c;n.startScan==="true"?c=await x(n.repositoryName,n.imageTag,n.scanType,s,i):c=await $(n.repositoryName,n.imageTag,n.scanType,s,i);let r=R(c,n.severity,n.ignoreFindings),u;if(n.sbom)if(n.scanType==="ENHANCED")try{let y=await M(n.repositoryName,n.imageTag,n.sbom.format,n.sbom.bucketName,n.sbom.kmsKeyArn);u={content:y.sbomContent,format:y.format}}catch(y){console.error(`SBOM export failed (non-fatal): ${y}`)}else console.log("SBOM export is only available with Enhanced scanning. Skipping SBOM generation.");let m=c.enhancedFindings.length>0?c.enhancedFindings:c.basicFindings,d=JSON.stringify(m,null,2),g=T(c,r,n.repositoryName,n.imageTag),l=await on(d,g,a,n.output,n.defaultLogGroupName,u);if(!r.hasVulnerabilities)return e;let f=`ECR Image Scan found vulnerabilities.
Image: ${a}
Scan Type: ${c.scanType}
Findings: ${r.summary}
See scan logs for details.`;if(n.vulnsTopicArn&&await D(n.vulnsTopicArn,f,a,l),n.failOnVulnerability==="false")return e;if(n.suppressErrorOnRollback==="true"&&await _(t.StackId))return console.log(`Vulnerabilities detected, but suppressing errors during rollback (suppressErrorOnRollback=true).
${f}`),e;throw new Error(f)},on=async(t,o,n,e,s,i)=>{switch(e?.type){case"cloudWatchLogs":return await v(t,o,e,n);case"s3":return await B(t,o,e,n,i);default:return console.log(`summary:
`+o),console.log(`findings:
`+t),{type:"default",logGroupName:s}}};0&&(module.exports={handler});
