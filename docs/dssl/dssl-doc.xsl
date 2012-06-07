<xsl:stylesheet version = '1.0'
     xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>

<xsl:template match="/">
     <xsl:apply-templates/>
</xsl:template>

<xsl:template match="dssl-doc">
    <html dir='ltr'>
    <head>
        <title>DSSL API Reference</title>
        <link rel="stylesheet" type="text/css" href="dssl-doc.css"/>
    </head>
    <body>
		<xsl:apply-templates/>
	</body>
	</html>
</xsl:template>

<xsl:template match="section">
	<h3><xsl:value-of select="@title"/></h3><hr/>
	<xsl:apply-templates select="descr"/>
	<xsl:apply-templates select="topic">
	</xsl:apply-templates>
</xsl:template>

<xsl:template match="topic">
	<h4><xsl:value-of select="@title"/></h4>
	<xsl:apply-templates select="descr"/>
	<xsl:apply-templates select="prototype"/>
	<xsl:apply-templates select="param-list"/>
</xsl:template>

<xsl:template match="descr">
	<p><xsl:value-of select="."/></p>
</xsl:template>

<xsl:template match="prototype">
	<pre style="background-color:#e0edff"><xsl:value-of select="."/></pre>
</xsl:template>

<xsl:template match="param-list">
	<div>Parameters:</div>
	<dl>
		<xsl:apply-templates select="param"/>
	</dl>
</xsl:template>

<xsl:template match="param">
	<dt><xsl:value-of select="@name"/></dt>
	<dd><xsl:value-of select="."/></dd>
</xsl:template>

</xsl:stylesheet>