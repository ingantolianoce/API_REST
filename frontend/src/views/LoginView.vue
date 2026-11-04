<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { messageFor } from '../api/http'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const router = useRouter()
const email = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const r = await auth.login(email.value, password.value)
    password.value = ''
    if (r.status === 'MFA_REQUIRED') await router.push('/mfa')
    else if (r.mustChangePassword) await router.push('/cambiar-clave')
    else if (r.mfaEnrollmentRequired) await router.push('/activar-mfa')
    else await router.push('/')
  } catch (e) {
    error.value = messageFor(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <h1>Ingresar</h1>
  <form @submit.prevent="submit">
    <label for="email">Correo</label>
    <input id="email" v-model="email" type="email" autocomplete="username" required maxlength="254" />
    <!-- Permite pegar y administradores de contrasenas (no se bloquea el pegado) -->
    <label for="password">Contraseña</label>
    <input id="password" v-model="password" type="password" autocomplete="current-password" required maxlength="256" />
    <button type="submit" :disabled="busy">Ingresar</button>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
  </form>
  <p><small>Al ingresar acepta el aviso de privacidad vigente (responsable, finalidades y derechos del titular).</small></p>
</template>
