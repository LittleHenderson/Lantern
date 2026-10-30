export default function Bio({ html }: { html: string }) {
  // planted: renders user-supplied HTML
  return <section dangerouslySetInnerHTML={{ __html: html }} />
}
