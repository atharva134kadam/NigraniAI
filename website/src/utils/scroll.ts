export function scrollToSection(sectionId: string) {
  const element = document.getElementById(sectionId);
  if (element) {
    const navbarHeight = 72;
    const elementPosition = element.getBoundingClientRect().top + window.pageYOffset;
    const offsetPosition = elementPosition - navbarHeight;

    window.scrollTo({
      top: offsetPosition,
      behavior: 'smooth'
    });
  }
}