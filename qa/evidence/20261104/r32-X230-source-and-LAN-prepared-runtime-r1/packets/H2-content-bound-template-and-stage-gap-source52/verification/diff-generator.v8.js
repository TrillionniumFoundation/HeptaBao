function unifiedDiff(before,after,from,to,context=3){
 const a=before.split("\n"),b=after.split("\n");if(a.at(-1)==="")a.pop();if(b.at(-1)==="")b.pop();
 const n=a.length,m=b.length,dp=Array.from({length:n+1},()=>new Uint16Array(m+1));
 for(let i=n-1;i>=0;i--)for(let j=m-1;j>=0;j--)dp[i][j]=a[i]===b[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
 const ops=[];let i=0,j=0;
 while(i<n||j<m){if(i<n&&j<m&&a[i]===b[j]){ops.push({kind:" ",text:a[i],old:i+1,new:j+1});i++;j++;}
 else if(i<n&&(j===m||dp[i+1][j]>=dp[i][j+1])){ops.push({kind:"-",text:a[i],old:i+1,new:j+1});i++;}
 else{ops.push({kind:"+",text:b[j],old:i+1,new:j+1});j++;}}
 const changed=ops.map((o,k)=>o.kind===" "?-1:k).filter(k=>k>=0),ranges=[];
 for(const k of changed){let start=Math.max(0,k-context),end=Math.min(ops.length,k+context+1);if(ranges.length&&start<=ranges.at(-1)[1])ranges.at(-1)[1]=Math.max(end,ranges.at(-1)[1]);else ranges.push([start,end]);}
 let out="--- "+from+"\n+++ "+to+"\n";
 for(const [lo,hi]of ranges){const r=ops.slice(lo,hi),oldCount=r.filter(x=>x.kind!=="+").length,newCount=r.filter(x=>x.kind!=="-").length,oldStart=oldCount?r[0].old:r[0].old-1,newStart=newCount?r[0].new:r[0].new-1;out+="@@ -"+oldStart+","+oldCount+" +"+newStart+","+newCount+" @@\n"+r.map(x=>x.kind+x.text+"\n").join("");}
 return out;
}
