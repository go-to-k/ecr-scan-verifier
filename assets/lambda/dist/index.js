"use strict";var E=Object.defineProperty;var U=Object.getOwnPropertyDescriptor;var K=Object.getOwnPropertyNames;var V=Object.prototype.hasOwnProperty;var H=(t,o)=>{for(var n in o)E(t,n,{get:o[n],enumerable:!0})},j=(t,o,n,e)=>{if(o&&typeof o=="object"||typeof o=="function")for(let s of K(o))!V.call(t,s)&&s!==n&&E(t,s,{get:()=>o[s],enumerable:!(e=U(o,s))||e.enumerable});return t};var X=t=>j(E({},"__esModule",{value:!0}),t);var rn={};H(rn,{handler:()=>W});module.exports=X(rn);var b=require("@aws-sdk/client-ecr"),N=new b.ECRClient,z=t=>new Promise(o=>setTimeout(o,t)),L=t=>t.startsWith("sha256:")?{imageDigest:t}:{imageTag:t},x=async(t,o,n,e,s)=>{let i=L(o);console.log(`Starting image scan for ${t}...`);try{await N.send(new b.StartImageScanCommand({repositoryName:t,imageId:i})),console.log("Image scan started successfully.")}catch(a){if(a.name==="LimitExceededException"||a.message&&a.message.includes("scan frequency limit"))console.log("Scan already in progress or recently completed, polling for results...");else throw a.name==="ValidationException"&&a.message&&a.message.includes("This feature is disabled")?new Error("StartImageScan is disabled because Enhanced scanning (Amazon Inspector) is enabled on this account. Use ScanConfig.enhanced() instead of ScanConfig.basic()."):a}return O(t,o,n,e,s)},O=async(t,o,n,e,s)=>{let i=L(o);for(let a=0;a<s;a++){console.log(`Polling scan results (attempt ${a+1}/${s})...`);try{let c=await q(t,i),r=c.rawResponse.imageScanStatus?.status;if(r==="COMPLETE"||r==="ACTIVE")return console.log(`Scan completed with status: ${r}`),c;if(r==="FAILED"){let u=c.rawResponse.imageScanStatus?.description||"Unknown error";throw new Error(`ECR image scan failed: ${u}`)}if(r==="UNSUPPORTED_IMAGE")throw new Error("ECR image scan failed: Image is not supported for scanning.");console.log(`Scan status: ${r}, waiting ${e}s...`)}catch(c){throw c.name==="ScanNotFoundException"?new Error("No scan results found for the image. Ensure that image scanning is enabled for this repository. If using Enhanced scanning (Amazon Inspector), verify that the repository is included in Inspector's coverage."):c}await z(e*1e3)}throw new Error(`ECR image scan timed out after ${s*e} seconds. The scan may still be in progress. Check the ECR console for results.`)},q=async(t,o)=>{let n=[],e=[],s,i;do{let r=await N.send(new b.DescribeImageScanFindingsCommand({repositoryName:t,imageId:o,nextToken:s,maxResults:1e3}));i=r,r.imageScanFindings?.findings&&n.push(...r.imageScanFindings.findings),r.imageScanFindings?.enhancedFindings&&e.push(...r.imageScanFindings.enhancedFindings),s=r.nextToken}while(s);let a=i?.imageScanFindings?.findingSeverityCounts?Object.fromEntries(Object.entries(i.imageScanFindings.findingSeverityCounts).map(([r,u])=>[r,u??0])):{};return{scanType:e.length>0?"ENHANCED":"BASIC",status:i?.imageScanStatus?.status??"UNKNOWN",basicFindings:n,enhancedFindings:e,severityCounts:a,rawResponse:i}};var k=(t,o,n)=>{let e=new Set(n),s=new Set(o);return t.scanType==="ENHANCED"?Y(t,s,e):J(t,s,e)},J=(t,o,n)=>{let e=t.basicFindings.filter(c=>!n.has(c.name||"")),s={},i=!1;for(let c of e){let r=c.severity||"UNDEFINED";s[r]=(s[r]||0)+1,o.has(r)&&(i=!0)}let a=R(s);return{hasVulnerabilities:i,summary:a,filteredSeverityCounts:s}},Y=(t,o,n)=>{let e=t.enhancedFindings.filter(c=>{if(n.has(c.findingArn||""))return!1;let r=c.packageVulnerabilityDetails?.vulnerabilityId;return!(r&&n.has(r))}),s={},i=!1;for(let c of e){let r=c.severity||"UNDEFINED";s[r]=(s[r]||0)+1,o.has(r)&&(i=!0)}let a=R(s);return{hasVulnerabilities:i,summary:a,filteredSeverityCounts:s}},R=t=>["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL","UNDEFINED"].filter(n=>t[n]).map(n=>`${n}: ${t[n]}`).join(", "),F=(t,o,n,e)=>{let s=["=== ECR Image Scan Results ===",`Repository: ${n}`,`Image: ${e}`,`Scan Type: ${t.scanType}`,`Scan Status: ${t.status}`,"","--- Severity Summary ---"];return o.summary?s.push(o.summary):s.push("No vulnerabilities found."),s.join(`
`)};var S=require("@aws-sdk/client-cloudwatch-logs"),T=new S.CloudWatchLogsClient,v=async(t,o,n,e)=>{let s=e.replace(/:/g,",").replace(/\//g,"_"),i=`${s}/findings`,a=`${s}/summary`,c=new Date().getTime();return await G(n.logGroupName,i,c,t),await G(n.logGroupName,a,c,o),console.log(`Scan logs output to the log group: ${n.logGroupName}
  findings stream: ${i}
  summary stream: ${a}`),{type:"cloudwatch",logGroupName:n.logGroupName,findingsLogStreamName:i,summaryLogStreamName:a}},P=1048576,Q=t=>{let n=new TextEncoder().encode(t);if(n.length<=P)return[t];let e=[],s=0,a=P-20;for(;s<n.length;){let c=n.slice(s,s+a),r=new TextDecoder("utf-8",{fatal:!1});e.push(r.decode(c)),s+=a}return e},G=async(t,o,n,e)=>{try{await T.send(new S.CreateLogStreamCommand({logGroupName:t,logStreamName:o}))}catch(u){if(u instanceof S.ResourceAlreadyExistsException)console.log(`Log stream ${o} already exists in log group ${t}.`);else throw u}let s=Q(e),i=s.length;i>1&&console.log(`Message size exceeds 1 MB limit. Splitting into ${i} chunks.`);let a=s.map((u,m)=>({timestamp:n+m,message:i>1?`[part ${m+1}/${i}] ${u}`:u})),c={logGroupName:t,logStreamName:o,logEvents:a},r=new S.PutLogEventsCommand(c);await T.send(r)};var C=require("@aws-sdk/client-s3");var I=new C.S3Client,A=async(t,o,n,e,s)=>{let i=new Date().toISOString(),a=e.replace(/:/g,"/").replace(/\//g,"_"),r=`${n.prefix?n.prefix.endsWith("/")?n.prefix:`${n.prefix}/`:""}${a}/${i}`,u=`${r}/findings.json`,m=`${r}/summary.txt`,p=[I.send(new C.PutObjectCommand({Bucket:n.bucketName,Key:u,Body:t,ContentType:"application/json"})),I.send(new C.PutObjectCommand({Bucket:n.bucketName,Key:m,Body:o,ContentType:"text/plain"}))],g;if(s){let d=s.format==="SPDX_2_3"?"spdx.json":"cyclonedx.json";g=`${r}/sbom.${d}`,p.push(I.send(new C.PutObjectCommand({Bucket:n.bucketName,Key:g,Body:s.content,ContentType:"application/json"})))}return await Promise.all(p),console.log(g?`Scan logs and SBOM output to S3:
  findings: s3://${n.bucketName}/${u}
  summary: s3://${n.bucketName}/${m}
  SBOM: s3://${n.bucketName}/${g}`:`Scan logs output to S3:
  findings: s3://${n.bucketName}/${u}
  summary: s3://${n.bucketName}/${m}`),{type:"s3",bucketName:n.bucketName,findingsKey:u,summaryKey:m,sbomKey:g}};var w=require("@aws-sdk/client-sns"),Z=new w.SNSClient,B=async(t,o,n,e)=>{let s="",i="";if(e.type==="cloudwatch")s=`CloudWatch Logs:
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
  summary: s3://${e.bucketName}/${e.summaryKey}${m}`;let p=e.sbomKey?`

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
\`\`\`${p}`}else e.type==="default"&&(s=`CloudWatch Logs:
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

${o}`,u={default:r,email:r,https:JSON.stringify(c)};try{await Z.send(new w.PublishCommand({TopicArn:t,Message:JSON.stringify(u),MessageStructure:"json"})),console.log(`Vulnerability notification sent to SNS topic: ${t}`)}catch(m){console.error(`Failed to send vulnerability notification to SNS: ${m}`)}};var y=require("@aws-sdk/client-cloudformation"),nn=new y.CloudFormationClient,D=async t=>{let o=new y.DescribeStacksCommand({StackName:t}),n=await nn.send(o);if(n.Stacks&&n.Stacks.length>0){let e=n.Stacks[0].StackStatus;return e===y.ResourceStatus.ROLLBACK_IN_PROGRESS||e===y.ResourceStatus.UPDATE_ROLLBACK_IN_PROGRESS}throw new Error(`Stack not found or no stacks returned from DescribeStacks command, stackId: ${t}`)};var f=require("@aws-sdk/client-inspector2"),h=require("@aws-sdk/client-s3"),M=new f.Inspector2Client,en=new h.S3Client,tn=t=>new Promise(o=>setTimeout(o,t)),_=async(t,o,n,e,s)=>{let i=n==="SPDX_2_3"?f.SbomReportFormat.SPDX_2_3:f.SbomReportFormat.CYCLONEDX_1_4;console.log(`Starting SBOM export for ${t} with format ${n}...`);let a={ecrRepositoryName:[{comparison:"EQUALS",value:t}],...o?{ecrImageTags:[{comparison:"EQUALS",value:o}]}:{}},r=(await M.send(new f.CreateSbomExportCommand({reportFormat:i,s3Destination:{bucketName:e,keyPrefix:`sbom-exports/${t}`,kmsKeyArn:s},resourceFilterCriteria:a}))).reportId;if(!r)throw new Error("CreateSbomExport did not return a reportId.");console.log(`SBOM export started with reportId: ${r}`);let u=60,m=5;for(let p=0;p<u;p++){let g=await M.send(new f.GetSbomExportCommand({reportId:r})),d=g.status;if(console.log(`SBOM export status: ${d} (attempt ${p+1}/${u})`),d==="SUCCEEDED"){let l=g.s3Destination?.keyPrefix,$=g.s3Destination?.bucketName;if(!$||!l)throw new Error("SBOM export succeeded but S3 destination is missing.");return{sbomContent:await sn($,l),format:n}}if(d==="FAILED"){let l=g.filterCriteria;throw new Error(`SBOM export failed. Filter criteria: ${JSON.stringify(l)}`)}if(d==="CANCELLED")throw new Error("SBOM export was cancelled.");await tn(m*1e3)}throw new Error(`SBOM export timed out after ${u*m} seconds.`)},sn=async(t,o)=>await(await en.send(new h.GetObjectCommand({Bucket:t,Key:o}))).Body?.transformToString()??"";var W=async function(t){let o=t.RequestType,n=t.ResourceProperties;if(!n.addr||!n.repositoryName)throw new Error("addr and repositoryName are required.");let e={PhysicalResourceId:n.addr,Data:{}};if(o!=="Create"&&o!=="Update")return e;let s=5,i=60,a=`${n.repositoryName}:${n.imageTag}`,c;n.startScan==="true"?c=await x(n.repositoryName,n.imageTag,n.scanType,s,i):c=await O(n.repositoryName,n.imageTag,n.scanType,s,i);let r=k(c,n.severity,n.ignoreFindings),u;if(n.sbom)if(n.scanType==="ENHANCED")try{let l=await _(n.repositoryName,n.imageTag,n.sbom.format,n.sbom.bucketName,n.sbom.kmsKeyArn);u={content:l.sbomContent,format:l.format}}catch(l){console.error(`SBOM export failed (non-fatal): ${l}`)}else console.log("SBOM export is only available with Enhanced scanning. Skipping SBOM generation.");let m=JSON.stringify(c.rawResponse.imageScanFindings,null,2),p=F(c,r,n.repositoryName,n.imageTag),g=await on(m,p,a,n.output,n.defaultLogGroupName,u);if(!r.hasVulnerabilities)return e;let d=`ECR Image Scan found vulnerabilities.
Image: ${a}
Scan Type: ${c.scanType}
Findings: ${r.summary}
See scan logs for details.`;if(n.vulnsTopicArn&&await B(n.vulnsTopicArn,d,a,g),n.failOnVulnerability==="false")return e;if(n.suppressErrorOnRollback==="true"&&await D(t.StackId))return console.log(`Vulnerabilities detected, but suppressing errors during rollback (suppressErrorOnRollback=true).
${d}`),e;throw new Error(d)},on=async(t,o,n,e,s,i)=>{switch(e?.type){case"cloudWatchLogs":return await v(t,o,e,n);case"s3":return await A(t,o,e,n,i);default:return console.log(`summary:
`+o),console.log(`findings:
`+t),{type:"default",logGroupName:s}}};0&&(module.exports={handler});
